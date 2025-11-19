"""
OSINT (Open Source Intelligence) Module
WHOIS, DNS, subdomain discovery, and geolocation
"""

import socket
import requests
from typing import Dict, List, Any
import logging
import json

logger = logging.getLogger(__name__)


class OSINTScanner:
    """
    OSINT tools for reconnaissance
    """
    
    def __init__(self, timeout: int = 10):
        """
        Initialize OSINT Scanner
        
        Args:
            timeout: Request timeout
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def gather_intelligence(self, domain: str) -> Dict[str, Any]:
        """
        Gather comprehensive OSINT data
        
        Args:
            domain: Target domain
            
        Returns:
            Dict with OSINT data
        """
        logger.info(f"Gathering OSINT for: {domain}")
        
        result = {
            'domain': domain,
            'whois': self.whois_lookup(domain),
            'dns_records': self.dns_lookup(domain),
            'subdomains': self.discover_subdomains(domain),
            'ip_info': self.ip_geolocation(domain)
        }
        
        return result
    
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup
        
        Args:
            domain: Target domain
            
        Returns:
            WHOIS information
        """
        logger.info(f"Performing WHOIS lookup for {domain}")
        
        try:
            # Simple WHOIS via socket
            whois_server = "whois.iana.org"
            port = 43
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((whois_server, port))
            sock.send((domain + "\r\n").encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            whois_data = response.decode('utf-8', errors='ignore')
            
            # Parse basic info
            parsed = self._parse_whois(whois_data)
            
            return parsed
        
        except Exception as e:
            logger.debug(f"WHOIS lookup error: {e}")
            return {'error': str(e)}
    
    def _parse_whois(self, whois_text: str) -> Dict[str, Any]:
        """Parse WHOIS response"""
        parsed = {'raw': whois_text[:1000]}
        
        lines = whois_text.split('\n')
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if 'registrar' in key and 'registrar' not in parsed:
                    parsed['registrar'] = value
                elif 'creation' in key or 'created' in key:
                    parsed['created_date'] = value
                elif 'expir' in key:
                    parsed['expiry_date'] = value
                elif 'status' in key:
                    parsed['status'] = value
        
        return parsed
    
    def dns_lookup(self, domain: str) -> Dict[str, List[str]]:
        """
        Perform DNS lookups (A, AAAA, MX, NS, TXT)
        
        Args:
            domain: Target domain
            
        Returns:
            DNS records
        """
        logger.info(f"Performing DNS lookup for {domain}")
        
        records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': []
        }
        
        try:
            # A records (IPv4)
            try:
                result = socket.getaddrinfo(domain, None, socket.AF_INET)
                records['A'] = list(set([r[4][0] for r in result]))
            except:
                pass
            
            # AAAA records (IPv6)
            try:
                result = socket.getaddrinfo(domain, None, socket.AF_INET6)
                records['AAAA'] = list(set([r[4][0] for r in result]))
            except:
                pass
            
            # For MX, NS, TXT we need a DNS library or external API
            # Using simple socket-based approach for basic info
            
        except Exception as e:
            logger.debug(f"DNS lookup error: {e}")
        
        return records
    
    def discover_subdomains(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """
        Discover subdomains using wordlist
        
        Args:
            domain: Target domain
            wordlist: List of subdomain names to test
            
        Returns:
            List of discovered subdomains
        """
        logger.info(f"Discovering subdomains for {domain}")
        
        if wordlist is None:
            # Common subdomain names
            wordlist = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test',
                'staging', 'api', 'app', 'cdn', 'portal', 'shop',
                'store', 'forum', 'support', 'help', 'vpn', 'remote',
                'cloud', 'secure', 'login', 'dashboard', 'panel'
            ]
        
        discovered = []
        
        for subdomain in wordlist:
            full_domain = f"{subdomain}.{domain}"
            
            try:
                socket.gethostbyname(full_domain)
                discovered.append(full_domain)
                logger.info(f"  ✓ Found: {full_domain}")
            except socket.gaierror:
                pass
            except Exception as e:
                logger.debug(f"Error checking {full_domain}: {e}")
        
        return discovered
    
    def ip_geolocation(self, target: str) -> Dict[str, Any]:
        """
        Get IP geolocation information
        
        Args:
            target: IP address or domain
            
        Returns:
            Geolocation data
        """
        logger.info(f"Getting geolocation for {target}")
        
        try:
            # Resolve domain to IP if needed
            ip = socket.gethostbyname(target)
            
            # Use free IP geolocation API
            url = f"http://ip-api.com/json/{ip}"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'ip': ip,
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'zip': data.get('zip'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as')
                }
        
        except Exception as e:
            logger.debug(f"Geolocation error: {e}")
            return {'error': str(e)}
    
    def check_breach(self, email: str) -> Dict[str, Any]:
        """
        Check if email appears in known breaches (placeholder)
        Note: Real implementation would use HIBP API or similar
        
        Args:
            email: Email address to check
            
        Returns:
            Breach information
        """
        logger.info(f"Checking breaches for {email}")
        
        # Placeholder - actual implementation would need proper API
        return {
            'email': email,
            'status': 'Check not available - use Have I Been Pwned API',
            'note': 'Implement with HIBP API key for production use'
        }
    
    def extract_metadata(self, url: str) -> Dict[str, Any]:
        """
        Extract metadata from webpage
        
        Args:
            url: Target URL
            
        Returns:
            Extracted metadata
        """
        logger.info(f"Extracting metadata from {url}")
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            metadata = {
                'title': soup.title.string if soup.title else None,
                'meta_description': None,
                'meta_keywords': None,
                'server': response.headers.get('Server'),
                'powered_by': response.headers.get('X-Powered-By'),
                'technologies': []
            }
            
            # Extract meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content = meta.get('content', '')
                
                if name == 'description':
                    metadata['meta_description'] = content
                elif name == 'keywords':
                    metadata['meta_keywords'] = content
            
            return metadata
        
        except Exception as e:
            logger.debug(f"Metadata extraction error: {e}")
            return {'error': str(e)}


# Example usage
if __name__ == "__main__":
    osint = OSINTScanner()
    
    result = osint.gather_intelligence("example.com")
    
    print(f"\nOSINT Results:")
    print(f"  Domain: {result['domain']}")
    print(f"  Subdomains found: {len(result.get('subdomains', []))}")
    print(f"  IP Info: {result.get('ip_info', {}).get('country')}")
