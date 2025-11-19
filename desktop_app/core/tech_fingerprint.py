"""
Technology Fingerprinting Module
Identifies web technologies, frameworks, and CMS
"""

import requests
import re
from typing import Dict, List, Any
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class TechFingerprint:
    """
    Technology detection and fingerprinting
    """
    
    # Technology signatures
    SIGNATURES = {
        'WordPress': {
            'headers': ['X-Powered-By.*WordPress'],
            'content': ['wp-content', 'wp-includes', 'wp-json'],
            'meta': ['generator.*WordPress']
        },
        'Joomla': {
            'headers': [],
            'content': ['/components/com_', '/media/jui/'],
            'meta': ['generator.*Joomla']
        },
        'Drupal': {
            'headers': ['X-Generator.*Drupal'],
            'content': ['/sites/default/', 'Drupal.settings'],
            'meta': ['generator.*Drupal']
        },
        'Shopify': {
            'headers': ['X-ShopId'],
            'content': ['cdn.shopify.com', 'myshopify.com'],
            'meta': []
        },
        'Magento': {
            'headers': [],
            'content': ['/static/version', 'Mage.Cookies'],
            'meta': []
        },
        'Laravel': {
            'headers': [],
            'content': ['laravel_session'],
            'meta': []
        },
        'Django': {
            'headers': ['X-Frame-Options.*django'],
            'content': ['csrftoken', '__admin__'],
            'meta': []
        },
        'React': {
            'headers': [],
            'content': ['react', 'react-dom', '_react'],
            'meta': []
        },
        'Vue.js': {
            'headers': [],
            'content': ['vue.js', 'vue.min.js', '__vue__'],
            'meta': []
        },
        'Angular': {
            'headers': [],
            'content': ['ng-app', 'ng-version', 'angular.js'],
            'meta': []
        },
        'jQuery': {
            'headers': [],
            'content': ['jquery.js', 'jquery.min.js'],
            'meta': []
        },
        'Bootstrap': {
            'headers': [],
            'content': ['bootstrap.css', 'bootstrap.js', 'bootstrap.min'],
            'meta': []
        },
        'Apache': {
            'headers': ['Server.*Apache'],
            'content': [],
            'meta': []
        },
        'Nginx': {
            'headers': ['Server.*nginx'],
            'content': [],
            'meta': []
        },
        'IIS': {
            'headers': ['Server.*IIS'],
            'content': [],
            'meta': []
        },
        'PHP': {
            'headers': ['X-Powered-By.*PHP'],
            'content': ['.php'],
            'meta': []
        },
        'ASP.NET': {
            'headers': ['X-AspNet-Version', 'X-Powered-By.*ASP.NET'],
            'content': ['__VIEWSTATE', '__EVENTVALIDATION'],
            'meta': []
        },
        'Node.js': {
            'headers': ['X-Powered-By.*Express'],
            'content': [],
            'meta': []
        },
        'Python': {
            'headers': ['Server.*Python'],
            'content': [],
            'meta': []
        }
    }
    
    def __init__(self, timeout: int = 10):
        """
        Initialize Technology Fingerprinting
        
        Args:
            timeout: Request timeout
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def fingerprint(self, url: str) -> Dict[str, Any]:
        """
        Identify technologies used by target
        
        Args:
            url: Target URL
            
        Returns:
            Dict with detected technologies
        """
        logger.info(f"Fingerprinting technologies for {url}")
        
        detected = {
            'url': url,
            'technologies': [],
            'cms': None,
            'web_server': None,
            'programming_language': [],
            'javascript_frameworks': [],
            'css_frameworks': []
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            content = response.text
            
            # Check each technology signature
            for tech, signatures in self.SIGNATURES.items():
                if self._check_technology(tech, signatures, headers, content):
                    detected['technologies'].append(tech)
                    
                    # Categorize technology
                    if tech in ['WordPress', 'Joomla', 'Drupal', 'Shopify', 'Magento']:
                        detected['cms'] = tech
                    elif tech in ['Apache', 'Nginx', 'IIS']:
                        detected['web_server'] = tech
                    elif tech in ['PHP', 'ASP.NET', 'Python', 'Node.js']:
                        detected['programming_language'].append(tech)
                    elif tech in ['React', 'Vue.js', 'Angular', 'jQuery']:
                        detected['javascript_frameworks'].append(tech)
                    elif tech in ['Bootstrap']:
                        detected['css_frameworks'].append(tech)
            
            # Extract version information
            detected['versions'] = self._extract_versions(headers, content)
            
            # Additional analysis
            detected['cookies'] = list(response.cookies.keys())
            detected['headers'] = dict(headers)
            
        except Exception as e:
            logger.error(f"Fingerprinting error: {e}")
            detected['error'] = str(e)
        
        return detected
    
    def _check_technology(self, tech: str, signatures: Dict, headers: Dict, content: str) -> bool:
        """Check if technology matches signatures"""
        
        # Check headers
        for pattern in signatures.get('headers', []):
            for header, value in headers.items():
                if re.search(pattern, f"{header}: {value}", re.IGNORECASE):
                    logger.info(f"  ✓ Detected {tech} (via headers)")
                    return True
        
        # Check content
        for pattern in signatures.get('content', []):
            if pattern.lower() in content.lower():
                logger.info(f"  ✓ Detected {tech} (via content)")
                return True
        
        # Check meta tags
        for pattern in signatures.get('meta', []):
            if re.search(pattern, content, re.IGNORECASE):
                logger.info(f"  ✓ Detected {tech} (via meta)")
                return True
        
        return False
    
    def _extract_versions(self, headers: Dict, content: str) -> Dict[str, str]:
        """Extract version information"""
        versions = {}
        
        # Check headers for versions
        for header, value in headers.items():
            # PHP version
            if 'PHP' in value:
                match = re.search(r'PHP/([\d.]+)', value)
                if match:
                    versions['PHP'] = match.group(1)
            
            # Apache version
            if 'Apache' in value:
                match = re.search(r'Apache/([\d.]+)', value)
                if match:
                    versions['Apache'] = match.group(1)
            
            # Nginx version
            if 'nginx' in value:
                match = re.search(r'nginx/([\d.]+)', value)
                if match:
                    versions['Nginx'] = match.group(1)
        
        # Check content for CMS versions
        # WordPress
        wp_match = re.search(r'WordPress ([\d.]+)', content)
        if wp_match:
            versions['WordPress'] = wp_match.group(1)
        
        # jQuery
        jq_match = re.search(r'jquery[.-]([\d.]+)', content, re.IGNORECASE)
        if jq_match:
            versions['jQuery'] = jq_match.group(1)
        
        return versions
    
    def detect_waf(self, url: str) -> Dict[str, Any]:
        """
        Detect Web Application Firewall
        
        Args:
            url: Target URL
            
        Returns:
            WAF detection results
        """
        logger.info(f"Detecting WAF for {url}")
        
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-', 'awselb'],
            'Akamai': ['akamai'],
            'Imperva': ['incap_ses', 'visid_incap'],
            'Sucuri': ['x-sucuri'],
            'ModSecurity': ['mod_security']
        }
        
        detected_waf = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers_str = str(response.headers).lower()
            
            for waf, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in headers_str:
                        detected_waf.append(waf)
                        logger.info(f"  ✓ Detected WAF: {waf}")
                        break
            
            return {
                'detected': len(detected_waf) > 0,
                'waf_list': detected_waf
            }
        
        except Exception as e:
            logger.debug(f"WAF detection error: {e}")
            return {'detected': False, 'error': str(e)}


# Example usage
if __name__ == "__main__":
    fingerprint = TechFingerprint()
    
    result = fingerprint.fingerprint("https://example.com")
    
    print(f"\nTechnology Fingerprint:")
    print(f"  CMS: {result.get('cms')}")
    print(f"  Web Server: {result.get('web_server')}")
    print(f"  Technologies: {', '.join(result.get('technologies', []))}")
