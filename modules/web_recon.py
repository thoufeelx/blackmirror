"""
Web reconnaissance module for technology fingerprinting and file discovery
"""

import requests
import re
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional
import subprocess
import os

class WebRecon:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.get('web.user_agent', 'Mozilla/5.0 (compatible; blackmirror/1.0)')
        })
        
    def scan(self, target: str, web_ports: List[str]) -> Dict[str, Any]:
        """Perform web reconnaissance on target"""
        results = {
            'technologies': [],
            'headers': {},
            'files': [],
            'directories': [],
            'forms': [],
            'javascript_files': [],
            'cookies': {},
            'server_info': None,
            'frameworks': [],
            'cms': None
        }
        
        # Determine protocols and ports
        protocols = []
        for port in web_ports:
            if port == '443' or port == '8443':
                protocols.append('https')
            else:
                protocols.append('http')
        
        # Scan each web service
        for i, port in enumerate(web_ports):
            protocol = protocols[i] if i < len(protocols) else 'http'
            url = f"{protocol}://{target}:{port}"
            
            try:
                # Basic web scan
                web_info = self._scan_web_service(url)
                results = self._merge_results(results, web_info)
                
                # Technology fingerprinting
                tech_info = self._fingerprint_technologies(url)
                results['technologies'].extend(tech_info)
                
                # File discovery
                files = self._discover_files(url)
                results['files'].extend(files)
                
                # Directory enumeration
                dirs = self._enumerate_directories(url)
                results['directories'].extend(dirs)
                
            except Exception as e:
                print(f"Error scanning {url}: {str(e)}")
        
        # Remove duplicates
        results['technologies'] = list(set(results['technologies']))
        results['files'] = list(set(results['files']))
        results['directories'] = list(set(results['directories']))
        
        return results
    
    def _scan_web_service(self, url: str) -> Dict[str, Any]:
        """Basic web service scan"""
        try:
            response = self.session.get(url, timeout=self.config.get('web.timeout', 10))
            
            results = {
                'headers': dict(response.headers),
                'server_info': response.headers.get('Server', 'Unknown'),
                'cookies': dict(response.cookies)
            }
            
            # Parse HTML for additional information
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract forms
                forms = []
                for form in soup.find_all('form'):
                    form_info = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get'),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all('input'):
                        form_info['inputs'].append({
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text')
                        })
                    
                    forms.append(form_info)
                
                results['forms'] = forms
                
                # Extract JavaScript files
                js_files = []
                for script in soup.find_all('script', src=True):
                    js_files.append(script['src'])
                
                results['javascript_files'] = js_files
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _fingerprint_technologies(self, url: str) -> List[str]:
        """Fingerprint web technologies"""
        technologies = []
        
        try:
            response = self.session.get(url, timeout=self.config.get('web.timeout', 10))
            headers = response.headers
            content = response.text.lower()
            
            # Server technologies
            server = headers.get('Server', '').lower()
            if 'apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('Nginx')
            elif 'iis' in server:
                technologies.append('IIS')
            elif 'cloudflare' in server:
                technologies.append('Cloudflare')
            
            # PHP detection
            if 'x-powered-by' in headers and 'php' in headers['x-powered-by'].lower():
                php_version = re.search(r'php/(\d+\.\d+)', headers['x-powered-by'], re.IGNORECASE)
                if php_version:
                    technologies.append(f"PHP {php_version.group(1)}")
                else:
                    technologies.append('PHP')
            
            # Framework detection
            if 'laravel' in content or 'laravel' in headers.get('x-powered-by', '').lower():
                technologies.append('Laravel')
            if 'django' in content or 'csrfmiddlewaretoken' in content:
                technologies.append('Django')
            if 'wordpress' in content or 'wp-content' in content:
                technologies.append('WordPress')
            if 'joomla' in content or 'joomla' in headers.get('x-powered-by', '').lower():
                technologies.append('Joomla')
            if 'drupal' in content:
                technologies.append('Drupal')
            
            # JavaScript frameworks
            if 'jquery' in content:
                technologies.append('jQuery')
            if 'react' in content or 'reactjs' in content:
                technologies.append('React')
            if 'angular' in content:
                technologies.append('Angular')
            if 'vue' in content:
                technologies.append('Vue.js')
            if 'bootstrap' in content:
                technologies.append('Bootstrap')
            
            # Database technologies
            if 'mysql' in content or 'mysqli' in content:
                technologies.append('MySQL')
            if 'postgresql' in content or 'postgres' in content:
                technologies.append('PostgreSQL')
            if 'mongodb' in content:
                technologies.append('MongoDB')
            
            # Security headers
            if 'x-frame-options' in headers:
                technologies.append('Security Headers')
            if 'hsts' in headers.get('strict-transport-security', '').lower():
                technologies.append('HSTS')
            
        except Exception as e:
            print(f"Error fingerprinting {url}: {str(e)}")
        
        return technologies
    
    def _discover_files(self, base_url: str) -> List[str]:
        """Discover interesting files"""
        interesting_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', '.htpasswd',
            'web.config', 'phpinfo.php', 'info.php', 'test.php',
            'admin.php', 'login.php', 'config.php', 'wp-config.php',
            'backup.zip', 'backup.tar.gz', 'backup.sql',
            '.git/config', '.env', 'config.ini', 'database.yml',
            'composer.json', 'package.json', 'requirements.txt',
            'README.md', 'CHANGELOG.md', 'LICENSE'
        ]
        
        discovered_files = []
        
        for file in interesting_files:
            try:
                url = urljoin(base_url, file)
                response = self.session.head(url, timeout=5)
                
                if response.status_code == 200:
                    discovered_files.append(file)
                    
            except Exception:
                continue
        
        return discovered_files
    
    def _enumerate_directories(self, base_url: str) -> List[str]:
        """Enumerate common directories"""
        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'wp-content',
            'api', 'api/v1', 'api/v2', 'rest', 'graphql',
            'backup', 'backups', 'old', 'archive',
            'dev', 'development', 'test', 'staging',
            'cgi-bin', 'bin', 'tmp', 'temp',
            'images', 'img', 'css', 'js', 'assets',
            'uploads', 'files', 'downloads',
            'config', 'conf', 'settings',
            'logs', 'log', 'debug'
        ]
        
        discovered_dirs = []
        
        for directory in common_dirs:
            try:
                url = urljoin(base_url, f"{directory}/")
                response = self.session.head(url, timeout=5)
                
                if response.status_code in [200, 301, 302, 403]:
                    discovered_dirs.append(directory)
                    
            except Exception:
                continue
        
        return discovered_dirs
    
    def _merge_results(self, base: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        """Merge scan results"""
        merged = base.copy()
        
        for key, value in new.items():
            if key in merged and isinstance(merged[key], list) and isinstance(value, list):
                merged[key].extend(value)
            elif key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key].update(value)
            else:
                merged[key] = value
        
        return merged
    
    def scan_with_whatweb(self, url: str) -> List[str]:
        """Use whatweb for additional technology detection"""
        technologies = []
        
        try:
            whatweb_path = self.config.get('tools.whatweb_path', 'whatweb')
            result = subprocess.run(
                [whatweb_path, '--no-errors', '--json', url],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, list) and len(data) > 0:
                        plugins = data[0].get('plugins', {})
                        for plugin, info in plugins.items():
                            if isinstance(info, dict) and info.get('version'):
                                technologies.append(f"{plugin} {info['version'][0]}")
                            else:
                                technologies.append(plugin)
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            print(f"Error running whatweb: {str(e)}")
        
        return technologies 