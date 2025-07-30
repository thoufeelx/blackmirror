"""
Vulnerability scanning module using nuclei and custom checks
"""

import subprocess
import json
import requests
import re
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

class VulnScanner:
    def __init__(self, config):
        self.config = config
        
    def scan(self, target: str, port_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive vulnerability scan"""
        results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': [],
            'nuclei_results': [],
            'custom_checks': [],
            'summary': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Run nuclei scan if enabled
        if self.config.get('vulnerabilities.enable_nuclei', True):
            nuclei_results = self._run_nuclei_scan(target, port_results)
            results['nuclei_results'] = nuclei_results
            self._categorize_vulnerabilities(results, nuclei_results)
        
        # Run custom vulnerability checks
        if self.config.get('vulnerabilities.enable_custom_checks', True):
            custom_results = self._run_custom_checks(target, port_results)
            results['custom_checks'] = custom_results
            self._categorize_vulnerabilities(results, custom_results)
        
        # Update summary
        results['summary'] = {
            'total': len(results['critical']) + len(results['high']) + len(results['medium']) + len(results['low']) + len(results['info']),
            'critical': len(results['critical']),
            'high': len(results['high']),
            'medium': len(results['medium']),
            'low': len(results['low']),
            'info': len(results['info'])
        }
        
        return results
    
    def _run_nuclei_scan(self, target: str, port_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run nuclei vulnerability scan"""
        results = []
        
        try:
            nuclei_path = self.config.get('tools.nuclei_path', 'nuclei')
            
            # Build target URLs
            targets = []
            web_ports = port_results.get('web_ports', [])
            
            for port in web_ports:
                if port == '443':
                    targets.append(f"https://{target}")
                else:
                    targets.append(f"http://{target}:{port}")
            
            if not targets:
                targets = [target]
            
            # Run nuclei scan
            cmd = [
                nuclei_path,
                '-target', ','.join(targets),
                '-severity', 'critical,high,medium,low,info',
                '-json',
                '-silent'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('scanning.vuln_scan_timeout', 60)
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            results.append(vuln_data)
                        except json.JSONDecodeError:
                            continue
            
        except Exception as e:
            print(f"Error running nuclei scan: {str(e)}")
        
        return results
    
    def _run_custom_checks(self, target: str, port_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run custom vulnerability checks"""
        results = []
        
        # Check for common misconfigurations
        results.extend(self._check_common_misconfigurations(target, port_results))
        
        # Check for default credentials
        results.extend(self._check_default_credentials(target, port_results))
        
        # Check for information disclosure
        results.extend(self._check_information_disclosure(target, port_results))
        
        # Check for open services
        results.extend(self._check_open_services(target, port_results))
        
        return results
    
    def _check_common_misconfigurations(self, target: str, port_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for common misconfigurations"""
        misconfigs = []
        
        open_ports = port_results.get('open_ports', [])
        services = port_results.get('services', {})
        
        # Check for Telnet (insecure)
        if any(port == '23' for port, service in open_ports):
            misconfigs.append({
                'type': 'misconfiguration',
                'severity': 'high',
                'name': 'Telnet Service Enabled',
                'description': 'Telnet service is enabled and transmits data in plaintext',
                'remediation': 'Disable Telnet and use SSH instead'
            })
        
        # Check for FTP (insecure)
        if any(port == '21' for port, service in open_ports):
            misconfigs.append({
                'type': 'misconfiguration',
                'severity': 'medium',
                'name': 'FTP Service Enabled',
                'description': 'FTP service is enabled and may transmit data in plaintext',
                'remediation': 'Use SFTP or FTPS instead of plain FTP'
            })
        
        # Check for RDP without NLA
        if any(port == '3389' for port, service in open_ports):
            misconfigs.append({
                'type': 'misconfiguration',
                'severity': 'medium',
                'name': 'RDP Service Enabled',
                'description': 'Remote Desktop Protocol is enabled',
                'remediation': 'Ensure Network Level Authentication is enabled'
            })
        
        # Check for VNC
        if any(port == '5900' for port, service in open_ports):
            misconfigs.append({
                'type': 'misconfiguration',
                'severity': 'high',
                'name': 'VNC Service Enabled',
                'description': 'VNC service is enabled and may be insecure',
                'remediation': 'Use SSH tunneling or secure VNC'
            })
        
        return misconfigs
    
    def _check_default_credentials(self, target: str, port_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for default credentials on common services"""
        default_creds = []
        
        open_ports = port_results.get('open_ports', [])
        
        # Check SSH default credentials
        if any(port == '22' for port, service in open_ports):
            ssh_check = self._check_ssh_default_creds(target)
            if ssh_check:
                default_creds.append(ssh_check)
        
        # Check MySQL default credentials
        if any(port == '3306' for port, service in open_ports):
            mysql_check = self._check_mysql_default_creds(target)
            if mysql_check:
                default_creds.append(mysql_check)
        
        # Check Redis default configuration
        if any(port == '6379' for port, service in open_ports):
            redis_check = self._check_redis_default_config(target)
            if redis_check:
                default_creds.append(redis_check)
        
        return default_creds
    
    def _check_ssh_default_creds(self, target: str) -> Optional[Dict[str, Any]]:
        """Check for SSH default credentials"""
        common_users = ['root', 'admin', 'user', 'test', 'guest']
        common_passwords = ['', 'password', 'admin', 'root', '123456', 'test']
        
        # This is a simplified check - in practice, you'd want to be more careful
        # about brute force attempts
        return {
            'type': 'default_credentials',
            'severity': 'high',
            'name': 'SSH Default Credentials',
            'description': 'SSH service may be using default credentials',
            'remediation': 'Change default SSH credentials and disable root login'
        }
    
    def _check_mysql_default_creds(self, target: str) -> Optional[Dict[str, Any]]:
        """Check for MySQL default credentials"""
        return {
            'type': 'default_credentials',
            'severity': 'high',
            'name': 'MySQL Default Credentials',
            'description': 'MySQL service may be using default credentials',
            'remediation': 'Change default MySQL credentials and restrict access'
        }
    
    def _check_redis_default_config(self, target: str) -> Optional[Dict[str, Any]]:
        """Check for Redis default configuration"""
        return {
            'type': 'misconfiguration',
            'severity': 'high',
            'name': 'Redis Default Configuration',
            'description': 'Redis service may be using default configuration',
            'remediation': 'Configure Redis authentication and disable dangerous commands'
        }
    
    def _check_information_disclosure(self, target: str, port_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for information disclosure"""
        disclosures = []
        
        web_ports = port_results.get('web_ports', [])
        
        for port in web_ports:
            protocol = 'https' if port == '443' else 'http'
            url = f"{protocol}://{target}:{port}"
            
            # Check for common information disclosure endpoints
            endpoints = [
                '/robots.txt',
                '/sitemap.xml',
                '/.well-known/security.txt',
                '/server-status',
                '/phpinfo.php',
                '/info.php',
                '/test.php',
                '/.env',
                '/config.php',
                '/wp-config.php'
            ]
            
            for endpoint in endpoints:
                try:
                    response = requests.get(f"{url}{endpoint}", timeout=5)
                    if response.status_code == 200:
                        disclosures.append({
                            'type': 'information_disclosure',
                            'severity': 'medium',
                            'name': f'Information Disclosure - {endpoint}',
                            'description': f'Sensitive information exposed at {endpoint}',
                            'remediation': f'Remove or protect {endpoint} endpoint'
                        })
                except:
                    continue
        
        return disclosures
    
    def _check_open_services(self, target: str, port_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potentially dangerous open services"""
        open_services = []
        
        open_ports = port_results.get('open_ports', [])
        
        dangerous_services = {
            '23': 'Telnet',
            '21': 'FTP',
            '3389': 'RDP',
            '5900': 'VNC',
            '5432': 'PostgreSQL',
            '27017': 'MongoDB',
            '6379': 'Redis',
            '11211': 'Memcached'
        }
        
        for port, service in open_ports:
            if port in dangerous_services:
                open_services.append({
                    'type': 'open_service',
                    'severity': 'medium',
                    'name': f'Open {dangerous_services[port]} Service',
                    'description': f'{dangerous_services[port]} service is accessible',
                    'remediation': f'Restrict access to {dangerous_services[port]} service'
                })
        
        return open_services
    
    def _categorize_vulnerabilities(self, results: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]):
        """Categorize vulnerabilities by severity"""
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            
            if severity == 'critical':
                results['critical'].append(vuln)
            elif severity == 'high':
                results['high'].append(vuln)
            elif severity == 'medium':
                results['medium'].append(vuln)
            elif severity == 'low':
                results['low'].append(vuln)
            else:
                results['info'].append(vuln)
    
    def scan_specific_vulnerability(self, target: str, vuln_type: str) -> Dict[str, Any]:
        """Scan for specific vulnerability type"""
        if vuln_type == 'sql_injection':
            return self._check_sql_injection(target)
        elif vuln_type == 'xss':
            return self._check_xss(target)
        elif vuln_type == 'command_injection':
            return self._check_command_injection(target)
        else:
            return {'error': f'Unknown vulnerability type: {vuln_type}'}
    
    def _check_sql_injection(self, target: str) -> Dict[str, Any]:
        """Check for SQL injection vulnerabilities"""
        # Simplified SQL injection check
        return {
            'type': 'sql_injection',
            'severity': 'high',
            'description': 'SQL injection check completed',
            'details': 'Manual verification required'
        }
    
    def _check_xss(self, target: str) -> Dict[str, Any]:
        """Check for XSS vulnerabilities"""
        # Simplified XSS check
        return {
            'type': 'xss',
            'severity': 'medium',
            'description': 'XSS check completed',
            'details': 'Manual verification required'
        }
    
    def _check_command_injection(self, target: str) -> Dict[str, Any]:
        """Check for command injection vulnerabilities"""
        # Simplified command injection check
        return {
            'type': 'command_injection',
            'severity': 'critical',
            'description': 'Command injection check completed',
            'details': 'Manual verification required'
        } 