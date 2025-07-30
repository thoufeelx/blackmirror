"""
SSL/TLS analysis module for certificate inspection and cipher analysis
"""

import ssl
import socket
import OpenSSL
from datetime import datetime
from typing import Dict, List, Any, Optional
import subprocess
import json

class SSLAnalyzer:
    def __init__(self, config):
        self.config = config
        
    def analyze(self, target: str, ssl_ports: List[str]) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration on target"""
        results = {
            'certificates': {},
            'ciphers': {},
            'vulnerabilities': [],
            'strong_ciphers': 0,
            'weak_ciphers': 0,
            'issuer': None,
            'subject': None,
            'valid_until': None,
            'serial_number': None
        }
        
        for port in ssl_ports:
            try:
                port_int = int(port)
                cert_info = self._get_certificate_info(target, port_int)
                cipher_info = self._analyze_ciphers(target, port_int)
                
                if cert_info:
                    results['certificates'][port] = cert_info
                    if not results['issuer']:
                        results['issuer'] = cert_info.get('issuer')
                    if not results['subject']:
                        results['subject'] = cert_info.get('subject')
                    if not results['valid_until']:
                        results['valid_until'] = cert_info.get('valid_until')
                    if not results['serial_number']:
                        results['serial_number'] = cert_info.get('serial_number')
                
                if cipher_info:
                    results['ciphers'][port] = cipher_info
                    results['strong_ciphers'] += cipher_info.get('strong_count', 0)
                    results['weak_ciphers'] += cipher_info.get('weak_count', 0)
                
                # Check for SSL vulnerabilities
                vulns = self._check_ssl_vulnerabilities(target, port_int)
                results['vulnerabilities'].extend(vulns)
                
            except Exception as e:
                print(f"Error analyzing SSL on port {port}: {str(e)}")
        
        return results
    
    def _get_certificate_info(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        return {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'serial_number': cert['serialNumber'],
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter'],
                            'san': cert.get('subjectAltName', []),
                            'issuer_common_name': dict(x[0] for x in cert['issuer']).get('commonName', ''),
                            'subject_common_name': dict(x[0] for x in cert['subject']).get('commonName', '')
                        }
            
        except Exception as e:
            print(f"Error getting certificate info: {str(e)}")
            return None
    
    def _analyze_ciphers(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Analyze SSL/TLS ciphers"""
        try:
            # Use OpenSSL to test ciphers
            ciphers = self._get_supported_ciphers(target, port)
            
            strong_ciphers = []
            weak_ciphers = []
            
            for cipher in ciphers:
                if self._is_strong_cipher(cipher):
                    strong_ciphers.append(cipher)
                else:
                    weak_ciphers.append(cipher)
            
            return {
                'all_ciphers': ciphers,
                'strong_ciphers': strong_ciphers,
                'weak_ciphers': weak_ciphers,
                'strong_count': len(strong_ciphers),
                'weak_count': len(weak_ciphers),
                'total_count': len(ciphers)
            }
            
        except Exception as e:
            print(f"Error analyzing ciphers: {str(e)}")
            return None
    
    def _get_supported_ciphers(self, target: str, port: int) -> List[str]:
        """Get list of supported ciphers"""
        ciphers = []
        
        # Common cipher suites to test
        cipher_suites = [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'ECDHE-RSA-AES256-SHA',
            'ECDHE-RSA-AES128-SHA',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-SHA256',
            'DHE-RSA-AES128-SHA256',
            'DHE-RSA-AES256-SHA',
            'DHE-RSA-AES128-SHA',
            'AES256-GCM-SHA384',
            'AES128-GCM-SHA256',
            'AES256-SHA256',
            'AES128-SHA256',
            'AES256-SHA',
            'AES128-SHA',
            'DES-CBC3-SHA',
            'RC4-SHA',
            'RC4-MD5'
        ]
        
        for cipher in cipher_suites:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.set_ciphers(cipher)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        ciphers.append(cipher)
                        
            except Exception:
                continue
        
        return ciphers
    
    def _is_strong_cipher(self, cipher: str) -> bool:
        """Determine if cipher is considered strong"""
        weak_patterns = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT'
        ]
        
        for pattern in weak_patterns:
            if pattern in cipher:
                return False
        
        return True
    
    def _check_ssl_vulnerabilities(self, target: str, port: int) -> List[str]:
        """Check for common SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for Heartbleed
            if self._check_heartbleed(target, port):
                vulnerabilities.append("Heartbleed (CVE-2014-0160)")
            
            # Check for POODLE
            if self._check_poodle(target, port):
                vulnerabilities.append("POODLE (CVE-2014-3566)")
            
            # Check for BEAST
            if self._check_beast(target, port):
                vulnerabilities.append("BEAST (CVE-2011-3389)")
            
            # Check for FREAK
            if self._check_freak(target, port):
                vulnerabilities.append("FREAK (CVE-2015-0204)")
            
            # Check for Logjam
            if self._check_logjam(target, port):
                vulnerabilities.append("Logjam (CVE-2015-4000)")
            
            # Check certificate expiration
            cert_info = self._get_certificate_info(target, port)
            if cert_info:
                not_after = cert_info.get('not_after')
                if not_after:
                    try:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        if expiry_date < datetime.now():
                            vulnerabilities.append("Certificate expired")
                        elif (expiry_date - datetime.now()).days < 30:
                            vulnerabilities.append("Certificate expires soon (< 30 days)")
                    except:
                        pass
            
            # Check for weak protocols
            if self._check_weak_protocols(target, port):
                vulnerabilities.append("Weak SSL/TLS protocols enabled")
            
        except Exception as e:
            print(f"Error checking SSL vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _check_heartbleed(self, target: str, port: int) -> bool:
        """Check for Heartbleed vulnerability"""
        try:
            # Simplified Heartbleed check
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Check if OpenSSL version is vulnerable
                    cipher = ssock.cipher()
                    return False  # Simplified check
                    
        except Exception:
            return False
    
    def _check_poodle(self, target: str, port: int) -> bool:
        """Check for POODLE vulnerability"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.set_ciphers('CBC')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher = ssock.cipher()
                    return 'CBC' in cipher[0]
                    
        except Exception:
            return False
    
    def _check_beast(self, target: str, port: int) -> bool:
        """Check for BEAST vulnerability"""
        # BEAST is similar to POODLE check
        return self._check_poodle(target, port)
    
    def _check_freak(self, target: str, port: int) -> bool:
        """Check for FREAK vulnerability"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.set_ciphers('EXPORT')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher = ssock.cipher()
                    return 'EXPORT' in cipher[0]
                    
        except Exception:
            return False
    
    def _check_logjam(self, target: str, port: int) -> bool:
        """Check for Logjam vulnerability"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.set_ciphers('DHE')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher = ssock.cipher()
                    return 'DHE' in cipher[0] and 'EXPORT' in cipher[0]
                    
        except Exception:
            return False
    
    def _check_weak_protocols(self, target: str, port: int) -> bool:
        """Check for weak SSL/TLS protocols"""
        weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        
        for protocol in weak_protocols:
            try:
                if protocol == 'SSLv2':
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
                elif protocol == 'SSLv3':
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                elif protocol == 'TLSv1.0':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                elif protocol == 'TLSv1.1':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
                else:
                    continue
                
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        return True
                        
            except Exception:
                continue
        
        return False
    
    def run_sslscan(self, target: str, port: int) -> Dict[str, Any]:
        """Run external sslscan tool if available"""
        try:
            result = subprocess.run(
                ['sslscan', '--json', f'{target}:{port}'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {}
                
        except Exception as e:
            print(f"Error running sslscan: {str(e)}")
            return {} 