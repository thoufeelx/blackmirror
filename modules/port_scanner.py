"""
Port scanning module using nmap
"""

import nmap
import subprocess
import socket
import threading
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    def __init__(self, config):
        self.config = config
        self.nm = nmap.PortScanner()
        
    def scan(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive port scan on target"""
        try:
            # Fast scan for common ports
            common_ports = "21-23,25,53,80,110-111,135,139,143,443,993,995,1723,3306,3389,5900,8080"
            
            # Run nmap scan
            scan_args = f"-sS -sV -O --version-intensity 5 -p {common_ports}"
            self.nm.scan(target, arguments=scan_args)
            
            results = {
                'open_ports': [],
                'services': {},
                'web_ports': [],
                'ssl_ports': [],
                'os_info': None
            }
            
            # Process scan results
            if target in self.nm.all_hosts():
                host = self.nm[target]
                
                # Extract open ports and services
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service_info = host[proto][port]
                        
                        if service_info['state'] == 'open':
                            port_str = str(port)
                            service_name = service_info.get('name', 'unknown')
                            
                            results['open_ports'].append((port_str, service_name))
                            results['services'][port_str] = service_info
                            
                            # Categorize ports
                            if service_name in ['http', 'https', 'www', 'web']:
                                results['web_ports'].append(port_str)
                            
                            if service_name == 'https' or port in [443, 8443, 9443]:
                                results['ssl_ports'].append(port_str)
                
                # OS detection
                if 'osmatch' in host and host['osmatch']:
                    os_info = host['osmatch'][0]
                    results['os_info'] = f"{os_info['name']} {os_info['accuracy']}%"
            
            # Additional quick scan for high ports if needed
            if not results['open_ports']:
                results.update(self._quick_scan(target))
            
            return results
            
        except Exception as e:
            return {
                'error': str(e),
                'open_ports': [],
                'services': {},
                'web_ports': [],
                'ssl_ports': [],
                'os_info': None
            }
    
    def _quick_scan(self, target: str) -> Dict[str, Any]:
        """Quick port scan using socket connections"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        results = {
            'open_ports': [],
            'services': {},
            'web_ports': [],
            'ssl_ports': [],
            'os_info': None
        }
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # Use thread pool for faster scanning
        with ThreadPoolExecutor(max_workers=self.config.get('scanning.max_threads', 10)) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in common_ports}
            
            for future in as_completed(future_to_port):
                port = future.result()
                if port:
                    port_str = str(port)
                    service_name = self._get_service_name(port)
                    
                    results['open_ports'].append((port_str, service_name))
                    results['services'][port_str] = {
                        'name': service_name,
                        'state': 'open',
                        'product': '',
                        'version': ''
                    }
                    
                    if service_name in ['http', 'https', 'www', 'web']:
                        results['web_ports'].append(port_str)
                    
                    if service_name == 'https' or port in [443, 8443, 9443]:
                        results['ssl_ports'].append(port_str)
        
        return results
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
            139: 'netbios-ssn', 143: 'imap', 443: 'https', 993: 'imaps',
            995: 'pop3s', 1723: 'pptp', 3306: 'mysql', 3389: 'ms-wbt-server',
            5900: 'vnc', 8080: 'http-proxy'
        }
        return service_map.get(port, 'unknown')
    
    def scan_custom_ports(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Scan specific ports"""
        try:
            port_str = ','.join(map(str, ports))
            scan_args = f"-sS -sV -p {port_str}"
            self.nm.scan(target, arguments=scan_args)
            
            results = {
                'open_ports': [],
                'services': {},
                'web_ports': [],
                'ssl_ports': []
            }
            
            if target in self.nm.all_hosts():
                host = self.nm[target]
                
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service_info = host[proto][port]
                        
                        if service_info['state'] == 'open':
                            port_str = str(port)
                            service_name = service_info.get('name', 'unknown')
                            
                            results['open_ports'].append((port_str, service_name))
                            results['services'][port_str] = service_info
            
            return results
            
        except Exception as e:
            return {
                'error': str(e),
                'open_ports': [],
                'services': {},
                'web_ports': [],
                'ssl_ports': []
            } 