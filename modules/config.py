"""
Configuration management for blackmirror
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    def __init__(self, config_path: str = 'config.yaml'):
        self.config_path = config_path
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'scanning': {
                'port_scan_timeout': 30,
                'web_scan_timeout': 10,
                'ssl_scan_timeout': 15,
                'vuln_scan_timeout': 60,
                'max_threads': 10
            },
            'apis': {
                'shodan_api_key': os.getenv('SHODAN_API_KEY', ''),
                'censys_api_id': os.getenv('CENSYS_API_ID', ''),
                'censys_api_secret': os.getenv('CENSYS_API_SECRET', ''),
                'virustotal_api_key': os.getenv('VIRUSTOTAL_API_KEY', '')
            },
            'tools': {
                'nmap_path': 'nmap',
                'masscan_path': 'masscan',
                'nuclei_path': 'nuclei',
                'whatweb_path': 'whatweb'
            },
            'web': {
                'user_agent': 'Mozilla/5.0 (compatible; blackmirror/1.0)',
                'timeout': 10,
                'follow_redirects': True,
                'max_redirects': 5
            },
            'vulnerabilities': {
                'enable_nuclei': True,
                'enable_custom_checks': True,
                'severity_levels': ['critical', 'high', 'medium', 'low']
            },
            'reporting': {
                'output_dir': 'reports',
                'include_timestamp': True,
                'include_screenshots': False
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self):
        """Save configuration to file"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
    
    def has_api_key(self, service: str) -> bool:
        """Check if API key is available for service"""
        api_keys = {
            'shodan': self.get('apis.shodan_api_key'),
            'censys': self.get('apis.censys_api_id') and self.get('apis.censys_api_secret'),
            'virustotal': self.get('apis.virustotal_api_key')
        }
        return bool(api_keys.get(service, False)) 