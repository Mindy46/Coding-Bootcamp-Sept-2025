"""
Loads configuration from JSON file or provides defaults
Keeps all the settings in one place which is nice
"""

import json
import os
from typing import Dict


class ConfigLoader:
    """
    Loads and manages configuration settings
    """
    
    def __init__(self, config_file: str = 'config.json'):
        """
        Initialize config loader
        
        Args:
            config_file: Path to JSON config file
        """
        self.config_file = config_file
    
    def load_config(self) -> Dict:
        """
        Load configuration from file
        
        Returns:
            Dictionary with configuration settings
        """
        if not os.path.exists(self.config_file):
            print(f"[WARNING] Config file not found: {self.config_file}")
            return self.get_default_config()
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            # Merge with defaults to ensure all keys exist
            default_config = self.get_default_config()
            default_config.update(config)
            
            return default_config
        
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON in config file: {e}")
            return self.get_default_config()
        except Exception as e:
            print(f"[ERROR] Error loading config: {e}")
            return self.get_default_config()
    
    @staticmethod
    def get_default_config() -> Dict:
        """
        Return default configuration
        
        These are reasonable defaults but can be overridden
        """
        return {
            # Threat detection thresholds
            'brute_force_threshold': 5,  # Number of failed attempts
            'brute_force_window_minutes': 10,  # Time window for attempts
            'port_scan_threshold': 10,  # Number of unique ports
            'injection_sensitivity': 'medium',  # low, medium, high
            
            # Alert settings
            'alert_methods': ['console', 'file'],  # console, file, email
            'alert_log_file': 'alerts.log',
            'email_alerts': False,
            'email_recipient': None,
            'email_smtp_server': None,
            'email_smtp_port': 587,
            
            # IP intelligence (for future use)
            'use_ip_geolocation': False,
            'geolocation_api_key': None,
            'use_threat_intel': False,
            'threat_intel_api_key': None,
            
            # Blacklist/Whitelist
            'ip_whitelist': [],  # IPs to never flag
            'ip_blacklist': [],  # IPs to always flag
            
            # Report settings
            'report_format': 'text',  # text, html, json
            'include_raw_logs': False,
            
            # Performance
            'max_log_entries': 100000,  # Stop parsing after this many
            'enable_caching': False
        }
    
    def save_config(self, config: Dict, output_file: str = None):
        """
        Save configuration to file
        
        Args:
            config: Configuration dictionary to save
            output_file: Optional different output path
        """
        output = output_file or self.config_file
        
        try:
            with open(output, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"[+] Configuration saved to: {output}")
        except Exception as e:
            print(f"[ERROR] Could not save config: {e}")
    
    def create_sample_config(self, output_file: str = 'config.json'):
        """
        Create a sample config file with comments (well, as JSON comments via description)
        """
        sample = self.get_default_config()
        
        # Add a README section
        sample['_README'] = (
            "This is the configuration file for Secure Log Analyzer. "
            "Adjust thresholds and settings as needed. "
            "Delete this _README key if you want."
        )
        
        self.save_config(sample, output_file)
        print(f"[+] Sample config created: {output_file}")
        print("    Edit this file to customize detection thresholds and alert settings")
    
    def validate_config(self, config: Dict) -> bool:
        """
        Validate configuration values
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Check critical fields
        required_fields = [
            'brute_force_threshold',
            'brute_force_window_minutes',
            'port_scan_threshold'
        ]
        
        for field in required_fields:
            if field not in config:
                print(f"[WARNING] Missing config field: {field}")
                return False
            
            # Check if values are reasonable
            if isinstance(config[field], (int, float)) and config[field] < 0:
                print(f"[WARNING] Invalid value for {field}: {config[field]}")
                return False
        
        # Validate alert methods
        valid_methods = ['console', 'file', 'email']
        for method in config.get('alert_methods', []):
            if method not in valid_methods:
                print(f"[WARNING] Unknown alert method: {method}")
        
        return True