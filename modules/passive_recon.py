"""
Passive reconnaissance module for WHOIS, Shodan, and Censys
"""

import whois
import requests
import json
from typing import Dict, List, Any, Optional
import socket
import dns.resolver

class PassiveRecon:
    def __init__(self, config):
        self.config = config
        
    def gather(self, target: str) -> Dict[str, Any]:
        """Gather passive reconnaissance data"""
        results = {
            'whois': {},
            'shodan': {},
            'censys': {},
            'dns': {},
            'subdomains': [],
            'reverse_dns': {},
            'asn': {},
            'geolocation': {}
        }
        
        # WHOIS lookup
        try:
            whois_data = self._get_whois_info(target)
            results['whois'] = whois_data
        except Exception as e:
            print(f"Error getting WHOIS info: {str(e)}")
        
        # DNS information
        try:
            dns_data = self._get_dns_info(target)
            results['dns'] = dns_data
        except Exception as e:
            print(f"Error getting DNS info: {str(e)}")
        
        # Reverse DNS
        try:
            reverse_dns = self._get_reverse_dns(target)
            results['reverse_dns'] = reverse_dns
        except Exception as e:
            print(f"Error getting reverse DNS: {str(e)}")
        
        # Shodan lookup (if API key available)
        if self.config.has_api_key('shodan'):
            try:
                shodan_data = self._get_shodan_info(target)
                results['shodan'] = shodan_data
            except Exception as e:
                print(f"Error getting Shodan info: {str(e)}")
        
        # Censys lookup (if API credentials available)
        if self.config.has_api_key('censys'):
            try:
                censys_data = self._get_censys_info(target)
                results['censys'] = censys_data
            except Exception as e:
                print(f"Error getting Censys info: {str(e)}")
        
        # ASN information
        try:
            asn_data = self._get_asn_info(target)
            results['asn'] = asn_data
        except Exception as e:
            print(f"Error getting ASN info: {str(e)}")
        
        # Geolocation
        try:
            geo_data = self._get_geolocation(target)
            results['geolocation'] = geo_data
        except Exception as e:
            print(f"Error getting geolocation: {str(e)}")
        
        return results
    
    def _get_whois_info(self, target: str) -> Dict[str, Any]:
        """Get WHOIS information"""
        try:
            w = whois.whois(target)
            
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'updated_date': w.updated_date,
                'status': w.status,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_dns_info(self, target: str) -> Dict[str, Any]:
        """Get DNS information"""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'ptr_records': []
        }
        
        try:
            # A records
            try:
                a_records = dns.resolver.resolve(target, 'A')
                dns_info['a_records'] = [str(record) for record in a_records]
            except:
                pass
            
            # AAAA records
            try:
                aaaa_records = dns.resolver.resolve(target, 'AAAA')
                dns_info['aaaa_records'] = [str(record) for record in aaaa_records]
            except:
                pass
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(target, 'MX')
                dns_info['mx_records'] = [str(record) for record in mx_records]
            except:
                pass
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(target, 'NS')
                dns_info['ns_records'] = [str(record) for record in ns_records]
            except:
                pass
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(target, 'TXT')
                dns_info['txt_records'] = [str(record) for record in txt_records]
            except:
                pass
            
            # CNAME records
            try:
                cname_records = dns.resolver.resolve(target, 'CNAME')
                dns_info['cname_records'] = [str(record) for record in cname_records]
            except:
                pass
            
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info
    
    def _get_reverse_dns(self, target: str) -> Dict[str, Any]:
        """Get reverse DNS information"""
        try:
            # Get IP address
            ip = socket.gethostbyname(target)
            
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                return {
                    'ip': ip,
                    'hostname': hostname,
                    'reverse_dns': hostname
                }
            except:
                return {
                    'ip': ip,
                    'hostname': None,
                    'reverse_dns': None
                }
                
        except Exception as e:
            return {'error': str(e)}
    
    def _get_shodan_info(self, target: str) -> Dict[str, Any]:
        """Get Shodan information"""
        try:
            import shodan
            
            api_key = self.config.get('apis.shodan_api_key')
            if not api_key:
                return {'error': 'Shodan API key not configured'}
            
            api = shodan.Shodan(api_key)
            
            # Search for the target
            results = api.search(f'hostname:{target}')
            
            shodan_data = {
                'total_results': results.get('total', 0),
                'matches': []
            }
            
            for match in results.get('matches', []):
                match_info = {
                    'ip': match.get('ip_str'),
                    'port': match.get('port'),
                    'product': match.get('product'),
                    'version': match.get('version'),
                    'os': match.get('os'),
                    'timestamp': match.get('timestamp'),
                    'data': match.get('data', '')[:500]  # Limit data size
                }
                shodan_data['matches'].append(match_info)
            
            return shodan_data
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_censys_info(self, target: str) -> Dict[str, Any]:
        """Get Censys information"""
        try:
            from censys.search import CensysHosts
            
            api_id = self.config.get('apis.censys_api_id')
            api_secret = self.config.get('apis.censys_api_secret')
            
            if not api_id or not api_secret:
                return {'error': 'Censys API credentials not configured'}
            
            c = CensysHosts(api_id=api_id, api_secret=api_secret)
            
            # Search for the target
            results = c.search(target)
            
            censys_data = {
                'total_results': 0,
                'matches': []
            }
            
            for hit in results:
                hit_info = {
                    'ip': hit.get('ip'),
                    'ports': hit.get('ports', []),
                    'services': hit.get('services', {}),
                    'location': hit.get('location', {}),
                    'autonomous_system': hit.get('autonomous_system', {}),
                    'last_updated': hit.get('last_updated')
                }
                censys_data['matches'].append(hit_info)
                censys_data['total_results'] += 1
            
            return censys_data
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_asn_info(self, target: str) -> Dict[str, Any]:
        """Get ASN information"""
        try:
            # Get IP address
            ip = socket.gethostbyname(target)
            
            # Query ASN information (simplified)
            # In a real implementation, you might use a service like IPinfo or similar
            return {
                'ip': ip,
                'asn': 'Unknown',
                'as_name': 'Unknown',
                'as_country': 'Unknown'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_geolocation(self, target: str) -> Dict[str, Any]:
        """Get geolocation information"""
        try:
            # Get IP address
            ip = socket.gethostbyname(target)
            
            # Use a free geolocation service
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip,
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'region': data.get('region'),
                    'region_name': data.get('regionName'),
                    'city': data.get('city'),
                    'zip': data.get('zip'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as')
                }
            else:
                return {'error': 'Failed to get geolocation data'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def find_subdomains(self, domain: str) -> List[str]:
        """Find subdomains using various techniques"""
        subdomains = []
        
        # Common subdomain list
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test',
            'staging', 'api', 'cdn', 'ns1', 'ns2', 'smtp', 'pop',
            'imap', 'webmail', 'support', 'help', 'docs', 'wiki',
            'forum', 'shop', 'store', 'app', 'mobile', 'secure',
            'login', 'portal', 'dashboard', 'cpanel', 'webdisk'
        ]
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
            except:
                continue
        
        return subdomains
    
    def get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive domain information"""
        info = {
            'domain': domain,
            'whois': self._get_whois_info(domain),
            'dns': self._get_dns_info(domain),
            'subdomains': self.find_subdomains(domain),
            'geolocation': self._get_geolocation(domain)
        }
        
        return info 