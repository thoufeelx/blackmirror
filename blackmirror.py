#!/usr/bin/env python3
"""
blackmirror - A powerful reconnaissance tool for cybersecurity professionals and students
Created by R Muhamme Thoufeel
"""

import sys
import os
import json
import time
import socket
import subprocess
import requests
import ssl
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urljoin, urlparse

# Rich imports for beautiful output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Rich library not available. Install with: pip install rich")
    print("Continuing with basic output...")

# Core imports
try:
    import nmap
    from bs4 import BeautifulSoup
    import dns.resolver
    import yaml
    import click
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

# Initialize console
console = Console() if RICH_AVAILABLE else None

def print_banner():
    """Display the blackmirror banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗███╗   ███╗██╗  ║
    ║    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝████╗ ████║██║  ║
    ║    ██████╔╝██║     ███████║██║     █████╔╝ ██╔████╔██║██║  ║
    ║    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║╚██╔╝██║██║  ║
    ║    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║ ╚═╝ ██║███████╗ ║
    ║    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ║
    ║                                                              ║
    ║              🔥 RECONNAISSANCE TOOL 🔥                      ║
    ║                                                              ║
    ║         Created by R Muhamme Thoufeel                        ║
    ║         Version: 2.0.0 | License: MIT                        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    
    if RICH_AVAILABLE:
        console.print(Panel(Align.center(banner), border_style="red"))
    else:
        print(banner)

def print_help():
    """Display comprehensive help menu"""
    help_text = """
    🔥 blackmirror - Reconnaissance Tool
    
    USAGE:
        python blackmirror.py <target> [options]
    
    EXAMPLES:
        python blackmirror.py example.com
        python blackmirror.py 192.168.1.10
        python blackmirror.py example.com --ports --web
        python blackmirror.py example.com --export markdown
    
    OPTIONS:
        --ports          Enable port scanning
        --web           Enable web reconnaissance  
        --ssl           Enable SSL/TLS analysis
        --vulns         Enable vulnerability scanning
        --passive       Enable passive reconnaissance
        --export FORMAT Export report (markdown/html/json)
        --quiet         Silent mode for automation
        --json          JSON output format
        --help          Show this help message
    
    MODULES:
        🔍 Port Scanner    - Fast port discovery with nmap
        🕵️ Web Recon      - Technology fingerprinting & file discovery
        🛡️ SSL Analyzer   - Certificate inspection & cipher analysis
        ⚡ Vuln Scanner   - Vulnerability detection & misconfigurations
        🌐 Passive Recon  - DNS, WHOIS, and basic intelligence
    
    FEATURES:
        ✅ No API keys required
        ✅ Works offline
        ✅ Student-friendly
        ✅ Professional-grade output
        ✅ Multiple export formats
        ✅ Automation ready
    
    LEGAL NOTICE:
        This tool is for authorized security testing only.
        Only scan targets you own or have permission to test.
        Users are responsible for compliance with local laws.
    
    Created by R Muhamme Thoufeel
    """
    
    if RICH_AVAILABLE:
        console.print(Panel(help_text, title="📖 Help", border_style="blue"))
    else:
        print(help_text)

def check_dependencies():
    """Check if all required dependencies are available"""
    dependencies = {
        'requests': 'HTTP requests',
        'nmap': 'Port scanning',
        'bs4': 'HTML parsing (beautifulsoup4)',
        'dns': 'DNS queries (dnspython)',
        'yaml': 'Configuration (pyyaml)',
        'click': 'CLI interface'
    }
    
    missing = []
    
    for module, description in dependencies.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(f"{module} ({description})")
    
    if missing:
        print("❌ Missing dependencies:")
        for dep in missing:
            print(f"   - {dep}")
        print("\nInstall with: pip install -r requirements.txt")
        return False
    
    return True

def check_external_tools():
    """Check if external tools are available"""
    tools = {
        'nmap': 'Port scanning tool'
    }
    
    missing = []
    
    for tool, description in tools.items():
        try:
            result = subprocess.run([tool, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                missing.append(f"{tool} ({description})")
        except FileNotFoundError:
            missing.append(f"{tool} ({description})")
    
    if missing:
        print("⚠️  Missing external tools:")
        for tool in missing:
            print(f"   - {tool}")
        print("\nInstall with:")
        print("   - nmap: sudo apt install nmap")
        return False
    
    return True

class BlackMirrorScanner:
    """Main scanner class with all reconnaissance capabilities"""
    
    def __init__(self, target: str):
        self.target = target
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; blackmirror/2.0)'
        })
        self.session.timeout = 10
    
    def scan_ports(self) -> Dict[str, Any]:
        """Perform port scanning"""
        try:
            if RICH_AVAILABLE:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                    task = progress.add_task("Scanning ports...", total=None)
                    
                    nm = nmap.PortScanner()
                    common_ports = "21-23,25,53,80,110-111,135,139,143,443,993,995,1723,3306,3389,5900,8080,8443"
                    
                    nm.scan(self.target, arguments=f"-sT -sV --version-intensity 5 -p {common_ports}")
                    
                    progress.update(task, description="Port scan completed")
            else:
                print("🔍 Scanning ports...")
                nm = nmap.PortScanner()
                common_ports = "21-23,25,53,80,110-111,135,139,143,443,993,995,1723,3306,3389,5900,8080,8443"
                nm.scan(self.target, arguments=f"-sT -sV --version-intensity 5 -p {common_ports}")
            
            results = {
                'open_ports': [],
                'services': {},
                'web_ports': [],
                'ssl_ports': [],
                'os_info': None
            }
            
            hosts = nm.all_hosts()
            if hosts:
                # Use the first host (resolved IP)
                host_ip = hosts[0]
                host = nm[host_ip]
                
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service_info = host[proto][port]
                        
                        if service_info['state'] == 'open':
                            port_str = str(port)
                            service_name = service_info.get('name', 'unknown')
                            service_version = service_info.get('version', '')
                            
                            results['open_ports'].append((port_str, service_name))
                            results['services'][port_str] = {
                                'name': service_name,
                                'version': service_version,
                                'product': service_info.get('product', ''),
                                'extrainfo': service_info.get('extrainfo', '')
                            }
                            
                            # Check for web ports
                            if service_name in ['http', 'https', 'www', 'web'] or port in [80, 443, 8080, 8443]:
                                results['web_ports'].append(port_str)
                            
                            # Check for SSL ports
                            if service_name == 'https' or port in [443, 8443, 9443]:
                                results['ssl_ports'].append(port_str)
                
                if 'osmatch' in host and host['osmatch']:
                    os_info = host['osmatch'][0]
                    results['os_info'] = f"{os_info['name']} {os_info['accuracy']}%"
            
            return results
            
        except Exception as e:
            print(f"❌ Port scan error: {e}")
            return {'error': str(e)}
    
    def scan_web(self, web_ports: List[str]) -> Dict[str, Any]:
        """Perform web reconnaissance"""
        try:
            if RICH_AVAILABLE:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                    task = progress.add_task("Web reconnaissance...", total=None)
                    
                    results = self._perform_web_scan(web_ports)
                    
                    progress.update(task, description="Web recon completed")
            else:
                print("🕵️ Web reconnaissance...")
                results = self._perform_web_scan(web_ports)
            
            return results
            
        except Exception as e:
            print(f"❌ Web scan error: {e}")
            return {'error': str(e)}
    
    def _perform_web_scan(self, web_ports: List[str]) -> Dict[str, Any]:
        """Perform actual web scanning"""
        results = {
            'technologies': [],
            'headers': {},
            'files': [],
            'directories': [],
            'forms': [],
            'technologies_detected': set()
        }
        
        protocols = []
        for port in web_ports:
            if port in ['443', '8443', '9443']:
                protocols.append('https')
            else:
                protocols.append('http')
        
        for i, port in enumerate(web_ports):
            protocol = protocols[i] if i < len(protocols) else 'http'
            url = f"{protocol}://{self.target}:{port}"
            
            try:
                response = self.session.get(url, timeout=10)
                headers = response.headers
                content = response.text.lower()
                
                # Technology detection
                if 'apache' in headers.get('Server', '').lower():
                    results['technologies_detected'].add('Apache')
                elif 'nginx' in headers.get('Server', '').lower():
                    results['technologies_detected'].add('Nginx')
                elif 'iis' in headers.get('Server', '').lower():
                    results['technologies_detected'].add('IIS')
                
                if 'x-powered-by' in headers and 'php' in headers['x-powered-by'].lower():
                    results['technologies_detected'].add('PHP')
                
                if 'wordpress' in content or 'wp-content' in content or 'wp-includes' in content:
                    results['technologies_detected'].add('WordPress')
                
                if 'jquery' in content:
                    results['technologies_detected'].add('jQuery')
                
                if 'bootstrap' in content:
                    results['technologies_detected'].add('Bootstrap')
                
                if 'react' in content or 'reactjs' in content:
                    results['technologies_detected'].add('React')
                
                if 'angular' in content:
                    results['technologies_detected'].add('Angular')
                
                if 'vue' in content:
                    results['technologies_detected'].add('Vue.js')
                
                if 'django' in content or 'csrfmiddlewaretoken' in content:
                    results['technologies_detected'].add('Django')
                
                if 'laravel' in content:
                    results['technologies_detected'].add('Laravel')
                
                if 'node' in content or 'express' in content:
                    results['technologies_detected'].add('Node.js')
                
                # Header analysis
                interesting_headers = ['server', 'x-powered-by', 'x-frame-options', 'x-content-type-options', 
                                    'x-xss-protection', 'strict-transport-security', 'content-security-policy']
                for header in interesting_headers:
                    if header in headers:
                        results['headers'][header] = headers[header]
                
                # File discovery
                interesting_files = ['robots.txt', 'sitemap.xml', '.htaccess', 'phpinfo.php', 'wp-config.php',
                                  'config.php', 'admin.php', 'login.php', 'test.php', 'info.php']
                for file in interesting_files:
                    try:
                        file_url = f"{url}/{file}"
                        file_response = self.session.head(file_url, timeout=5)
                        if file_response.status_code == 200:
                            results['files'].append(file)
                    except:
                        continue
                
                # Form analysis
                soup = BeautifulSoup(content, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    form_info = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get'),
                        'inputs': []
                    }
                    
                    inputs = form.find_all('input')
                    for inp in inputs:
                        input_info = {
                            'type': inp.get('type', 'text'),
                            'name': inp.get('name', ''),
                            'id': inp.get('id', '')
                        }
                        form_info['inputs'].append(input_info)
                    
                    results['forms'].append(form_info)
                
            except Exception as e:
                print(f"Error scanning {url}: {e}")
        
        results['technologies'] = list(results['technologies_detected'])
        return results
    
    def scan_ssl(self, ssl_ports: List[str]) -> Dict[str, Any]:
        """Perform SSL/TLS analysis"""
        try:
            if RICH_AVAILABLE:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                    task = progress.add_task("SSL analysis...", total=None)
                    
                    results = self._perform_ssl_scan(ssl_ports)
                    
                    progress.update(task, description="SSL analysis completed")
            else:
                print("🛡️ SSL analysis...")
                results = self._perform_ssl_scan(ssl_ports)
            
            return results
            
        except Exception as e:
            print(f"❌ SSL scan error: {e}")
            return {'error': str(e)}
    
    def _perform_ssl_scan(self, ssl_ports: List[str]) -> Dict[str, Any]:
        """Perform actual SSL scanning"""
        results = {
            'certificates': {},
            'vulnerabilities': [],
            'strong_ciphers': 0,
            'weak_ciphers': 0,
            'ssl_issues': []
        }
        
        for port in ssl_ports:
            try:
                port_int = int(port)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, port_int), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        
                        if cert:
                            results['certificates'][port] = {
                                'subject': dict(x[0] for x in cert['subject']),
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'not_after': cert['notAfter'],
                                'not_before': cert['notBefore']
                            }
                        
                        # Basic cipher check
                        cipher = ssock.cipher()
                        if cipher:
                            cipher_name = cipher[0].lower()
                            if any(weak in cipher_name for weak in ['rc4', 'des', 'md5', 'sha1']):
                                results['weak_ciphers'] += 1
                                results['ssl_issues'].append(f"Weak cipher on port {port}: {cipher[0]}")
                            else:
                                results['strong_ciphers'] += 1
                
            except Exception as e:
                print(f"Error analyzing SSL on port {port}: {e}")
        
        return results
    
    def scan_vulnerabilities(self, port_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform vulnerability scanning"""
        try:
            if RICH_AVAILABLE:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                    task = progress.add_task("Vulnerability scanning...", total=None)
                    
                    results = self._perform_vuln_scan(port_results)
                    
                    progress.update(task, description="Vulnerability scan completed")
            else:
                print("⚡ Vulnerability scanning...")
                results = self._perform_vuln_scan(port_results)
            
            return results
            
        except Exception as e:
            print(f"❌ Vulnerability scan error: {e}")
            return {'error': str(e)}
    
    def _perform_vuln_scan(self, port_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform actual vulnerability scanning"""
        results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        open_ports = port_results.get('open_ports', [])
        
        # Check for common misconfigurations
        for port, service in open_ports:
            if port == '23':
                results['high'].append({
                    'name': 'Telnet Service Enabled',
                    'description': 'Telnet transmits data in plaintext',
                    'remediation': 'Disable Telnet and use SSH'
                })
            
            elif port == '21':
                results['medium'].append({
                    'name': 'FTP Service Enabled',
                    'description': 'FTP may transmit data in plaintext',
                    'remediation': 'Use SFTP or FTPS'
                })
            
            elif port == '3389':
                results['medium'].append({
                    'name': 'RDP Service Enabled',
                    'description': 'Remote Desktop Protocol is accessible',
                    'remediation': 'Enable Network Level Authentication'
                })
            
            elif port == '22':
                results['low'].append({
                    'name': 'SSH Service Enabled',
                    'description': 'SSH service is accessible',
                    'remediation': 'Ensure SSH is properly configured'
                })
        
        # Check for information disclosure
        web_ports = port_results.get('web_ports', [])
        for port in web_ports:
            protocol = 'https' if port == '443' else 'http'
            url = f"{protocol}://{self.target}:{port}"
            
            try:
                response = self.session.get(f"{url}/robots.txt", timeout=5)
                if response.status_code == 200:
                    results['low'].append({
                        'name': 'Information Disclosure - robots.txt',
                        'description': 'robots.txt file is accessible',
                        'remediation': 'Review and secure exposed directories'
                    })
            except:
                pass
            
            try:
                response = self.session.get(f"{url}/.git/HEAD", timeout=5)
                if response.status_code == 200:
                    results['high'].append({
                        'name': 'Git Repository Exposed',
                        'description': '.git directory is accessible',
                        'remediation': 'Remove or secure .git directory'
                    })
            except:
                pass
        
        return results
    
    def scan_passive(self) -> Dict[str, Any]:
        """Perform passive reconnaissance"""
        try:
            if RICH_AVAILABLE:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                    task = progress.add_task("Passive reconnaissance...", total=None)
                    
                    results = self._perform_passive_scan()
                    
                    progress.update(task, description="Passive recon completed")
            else:
                print("🌐 Passive reconnaissance...")
                results = self._perform_passive_scan()
            
            return results
            
        except Exception as e:
            print(f"❌ Passive scan error: {e}")
            return {'error': str(e)}
    
    def _perform_passive_scan(self) -> Dict[str, Any]:
        """Perform actual passive scanning"""
        results = {
            'dns': {},
            'geolocation': {}
        }
        
        # DNS lookup
        try:
            a_records = dns.resolver.resolve(self.target, 'A')
            results['dns']['a_records'] = [str(record) for record in a_records]
        except:
            pass
        
        try:
            mx_records = dns.resolver.resolve(self.target, 'MX')
            results['dns']['mx_records'] = [str(record) for record in mx_records]
        except:
            pass
        
        try:
            ns_records = dns.resolver.resolve(self.target, 'NS')
            results['dns']['ns_records'] = [str(record) for record in ns_records]
        except:
            pass
        
        # Basic geolocation (simplified)
        try:
            ip = socket.gethostbyname(self.target)
            results['geolocation']['ip'] = ip
        except:
            pass
        
        return results
    
    def run_full_scan(self) -> Dict[str, Any]:
        """Run complete reconnaissance scan"""
        print(f"\n🎯 Starting reconnaissance on: {self.target}\n")
        
        # Port scanning
        self.results['ports'] = self.scan_ports()
        
        # Web reconnaissance
        if self.results['ports'].get('web_ports'):
            self.results['web'] = self.scan_web(self.results['ports']['web_ports'])
        
        # SSL analysis
        if self.results['ports'].get('ssl_ports'):
            self.results['ssl'] = self.scan_ssl(self.results['ports']['ssl_ports'])
        
        # Vulnerability scanning
        self.results['vulns'] = self.scan_vulnerabilities(self.results['ports'])
        
        # Passive reconnaissance
        self.results['passive'] = self.scan_passive()
        
        return self.results
    
    def display_results(self):
        """Display results in beautiful format"""
        if not RICH_AVAILABLE:
            self._display_results_basic()
            return
        
        console.print("\n" + "="*80)
        console.print(f"[bold green]🎯 RECONNAISSANCE RESULTS FOR: {self.target}[/bold green]")
        console.print("="*80 + "\n")
        
        # Port Scan Results
        if self.results.get('ports'):
            self._display_ports_rich()
        
        # Web Recon Results
        if self.results.get('web'):
            self._display_web_rich()
        
        # SSL Analysis Results
        if self.results.get('ssl'):
            self._display_ssl_rich()
        
        # Vulnerability Results
        if self.results.get('vulns'):
            self._display_vulns_rich()
        
        # Passive Recon Results
        if self.results.get('passive'):
            self._display_passive_rich()
        
        # Summary
        self._display_summary_rich()
    
    def _display_ports_rich(self):
        """Display port scan results with rich"""
        ports = self.results['ports']
        
        panel_content = f"""
[bold]Open Ports:[/bold] {', '.join([f"{p} ({s})" for p, s in ports.get('open_ports', [])])}

[bold]Service Detection:[/bold]
"""
        
        for port, service_info in ports.get('services', {}).items():
            service_name = service_info.get('name', 'unknown')
            service_version = service_info.get('version', '')
            service_product = service_info.get('product', '')
            
            if service_version or service_product:
                panel_content += f"  • Port {port}: {service_name} {service_version} {service_product}\n"
            else:
                panel_content += f"  • Port {port}: {service_name}\n"
        
        if ports.get('os_info'):
            panel_content += f"\n[bold]OS Detection:[/bold] {ports['os_info']}"
        
        console.print(Panel(panel_content, title="🔍 Port Scan", border_style="blue"))
    
    def _display_web_rich(self):
        """Display web reconnaissance results with rich"""
        web = self.results['web']
        
        panel_content = f"""
[bold]Technologies Detected:[/bold]
"""
        
        for tech in web.get('technologies', []):
            panel_content += f"  • {tech}\n"
        
        if web.get('headers'):
            panel_content += f"\n[bold]Interesting Headers:[/bold]\n"
            for header, value in web.get('headers', {}).items():
                panel_content += f"  • {header}: {value}\n"
        
        if web.get('files'):
            panel_content += f"\n[bold]Interesting Files:[/bold]\n"
            for file in web.get('files', []):
                panel_content += f"  • {file}\n"
        
        if web.get('forms'):
            panel_content += f"\n[bold]Forms Found:[/bold] {len(web.get('forms', []))}"
        
        console.print(Panel(panel_content, title="🕵️ Web Recon", border_style="green"))
    
    def _display_ssl_rich(self):
        """Display SSL analysis results with rich"""
        ssl = self.results['ssl']
        
        panel_content = f"""
[bold]Certificate Information:[/bold]
"""
        
        for port, cert in ssl.get('certificates', {}).items():
            issuer = cert.get('issuer', {}).get('commonName', 'Unknown')
            panel_content += f"  • Port {port}: {issuer}\n"
        
        panel_content += f"\n[bold]Cipher Analysis:[/bold]\n"
        panel_content += f"  • Strong Ciphers: {ssl.get('strong_ciphers', 0)}\n"
        panel_content += f"  • Weak Ciphers: {ssl.get('weak_ciphers', 0)}\n"
        
        if ssl.get('ssl_issues'):
            panel_content += f"\n[bold]SSL Issues:[/bold]\n"
            for issue in ssl.get('ssl_issues', []):
                panel_content += f"  • {issue}\n"
        
        console.print(Panel(panel_content, title="🛡️ SSL Analysis", border_style="yellow"))
    
    def _display_vulns_rich(self):
        """Display vulnerability results with rich"""
        vulns = self.results['vulns']
        
        panel_content = ""
        
        if vulns.get('critical'):
            panel_content += f"\n[bold red]Critical Vulnerabilities:[/bold red]\n"
            for vuln in vulns['critical']:
                panel_content += f"  • {vuln['name']}\n"
        
        if vulns.get('high'):
            panel_content += f"\n[bold orange]High Risk Vulnerabilities:[/bold orange]\n"
            for vuln in vulns['high']:
                panel_content += f"  • {vuln['name']}\n"
        
        if vulns.get('medium'):
            panel_content += f"\n[bold yellow]Medium Risk Vulnerabilities:[/bold yellow]\n"
            for vuln in vulns['medium']:
                panel_content += f"  • {vuln['name']}\n"
        
        if vulns.get('low'):
            panel_content += f"\n[bold blue]Low Risk Vulnerabilities:[/bold blue]\n"
            for vuln in vulns['low']:
                panel_content += f"  • {vuln['name']}\n"
        
        if not any([vulns.get('critical'), vulns.get('high'), vulns.get('medium'), vulns.get('low')]):
            panel_content = "\n[bold green]✅ No vulnerabilities detected![/bold green]\n"
        
        console.print(Panel(panel_content, title="🛡️ Vulnerabilities", border_style="red"))
    
    def _display_passive_rich(self):
        """Display passive reconnaissance results with rich"""
        passive = self.results['passive']
        
        panel_content = ""
        
        if passive.get('dns'):
            panel_content += f"[bold]DNS Records:[/bold]\n"
            for record_type, records in passive['dns'].items():
                panel_content += f"  • {record_type.upper()}: {', '.join(records)}\n"
        
        if passive.get('geolocation'):
            panel_content += f"\n[bold]IP Information:[/bold]\n"
            panel_content += f"  • IP: {passive['geolocation'].get('ip', 'Unknown')}\n"
        
        console.print(Panel(panel_content, title="🌐 Passive Recon", border_style="cyan"))
    
    def _display_summary_rich(self):
        """Display summary with rich"""
        ports = self.results.get('ports', {})
        web = self.results.get('web', {})
        vulns = self.results.get('vulns', {})
        
        table = Table(title="📊 Executive Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_column("Status", style="green")
        
        open_ports = len(ports.get('open_ports', []))
        table.add_row("Open Ports", str(open_ports), "⚠️" if open_ports > 0 else "✅")
        
        tech_count = len(web.get('technologies', []))
        table.add_row("Web Technologies", str(tech_count), "ℹ️")
        
        critical_vulns = len(vulns.get('critical', []))
        table.add_row("Critical Vulnerabilities", str(critical_vulns), "🔴" if critical_vulns > 0 else "✅")
        
        high_vulns = len(vulns.get('high', []))
        table.add_row("High Risk Vulnerabilities", str(high_vulns), "🟠" if high_vulns > 0 else "✅")
        
        medium_vulns = len(vulns.get('medium', []))
        table.add_row("Medium Risk Vulnerabilities", str(medium_vulns), "🟡" if medium_vulns > 0 else "✅")
        
        console.print(table)
    
    def _display_results_basic(self):
        """Display results in basic format"""
        print(f"\n🎯 RECONNAISSANCE RESULTS FOR: {self.target}")
        print("="*80)
        
        # Port Scan Results
        if self.results.get('ports'):
            ports = self.results['ports']
            print("\n🔍 PORT SCAN RESULTS:")
            print("-" * 40)
            
            for port, service in ports.get('open_ports', []):
                print(f"  • Port {port} ({service})")
            
            if ports.get('os_info'):
                print(f"  • OS: {ports['os_info']}")
        
        # Web Recon Results
        if self.results.get('web'):
            web = self.results['web']
            print("\n🕵️ WEB RECONNAISSANCE:")
            print("-" * 40)
            
            for tech in web.get('technologies', []):
                print(f"  • {tech}")
            
            for file in web.get('files', []):
                print(f"  • File: {file}")
        
        # Vulnerability Results
        if self.results.get('vulns'):
            vulns = self.results['vulns']
            print("\n🛡️ VULNERABILITIES:")
            print("-" * 40)
            
            for severity in ['critical', 'high', 'medium', 'low']:
                for vuln in vulns.get(severity, []):
                    print(f"  • {severity.upper()}: {vuln['name']}")
    
    def export_report(self, format_type: str) -> str:
        """Export report in specified format"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create reports directory
        os.makedirs('reports', exist_ok=True)
        
        if format_type == 'json':
            filename = f"reports/recon-{self.target}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump({
                    'target': self.target,
                    'scan_date': timestamp,
                    'results': self.results
                }, f, indent=2)
        
        elif format_type == 'markdown':
            filename = f"reports/recon-{self.target}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
            with open(filename, 'w') as f:
                f.write(f"# Reconnaissance Report\n\n")
                f.write(f"**Target:** {self.target}\n")
                f.write(f"**Scan Date:** {timestamp}\n")
                f.write(f"**Generated by:** blackmirror (R Muhamme Thoufeel)\n\n")
                
                # Add results sections
                if self.results.get('ports'):
                    f.write("## Port Scan Results\n\n")
                    for port, service in self.results['ports'].get('open_ports', []):
                        f.write(f"- Port {port} ({service})\n")
                    f.write("\n")
        
        return filename

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print_banner()
        print_help()
        sys.exit(1)
    
    # Parse arguments
    target = sys.argv[1]
    options = sys.argv[2:] if len(sys.argv) > 2 else []
    
    # Handle help
    if target in ['--help', '-h', 'help'] or '--help' in options or '-h' in options:
        print_banner()
        print_help()
        sys.exit(0)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check external tools
    if not check_external_tools():
        print("⚠️  Some features may not work properly")
    
    # Initialize scanner
    scanner = BlackMirrorScanner(target)
    
    try:
        # Run scan
        results = scanner.run_full_scan()
        
        # Display results
        scanner.display_results()
        
        # Export if requested
        if '--export' in options:
            export_index = options.index('--export')
            if export_index + 1 < len(options):
                format_type = options[export_index + 1]
                if format_type in ['json', 'markdown', 'html']:
                    filename = scanner.export_report(format_type)
                    print(f"\n📄 Report saved to: {filename}")
        
        # JSON output
        if '--json' in options:
            print(json.dumps(results, indent=2))
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 