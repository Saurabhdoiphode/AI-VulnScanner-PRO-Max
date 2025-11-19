"""
Open Redirect Scanner Module
Detects open redirect vulnerabilities
"""

import requests
import urllib.parse
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class OpenRedirectScanner:
    """
    Open Redirect vulnerability scanner
    Detects unvalidated redirects and forwards
    """
    
    # Open redirect test payloads
    REDIRECT_PAYLOADS = [
        # External domains
        "https://evil.com",
        "http://evil.com",
        "//evil.com",
        "///evil.com",
        "////evil.com",
        
        # Protocol handlers
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        
        # URL encoding bypass
        "https%3A%2F%2Fevil.com",
        "%2F%2Fevil.com",
        
        # Double encoding
        "https%253A%252F%252Fevil.com",
        
        # CRLF injection in redirect
        "/%0d%0aLocation:%20https://evil.com",
        
        # Backslash tricks
        "https://evil.com\\",
        "https:\\\\evil.com",
        
        # @ symbol tricks
        "https://legitimate.com@evil.com",
        "https://legitimate.com%2540evil.com",
        
        # Dots and subdomain tricks
        "https://evil.com.legitimate.com",
        "https://legitimateevil.com",
        
        # Absolute path to external
        "//google.com/%2f..",
        
        # Whitespace
        "https://evil.com%20",
        " https://evil.com",
        
        # Null byte
        "https://evil.com%00",
        
        # Mixed encoding
        "https://evil.com%E3%80%82",
    ]
    
    # Redirect parameter names commonly used
    REDIRECT_PARAMS = [
        'url', 'redirect', 'redirect_url', 'redirect_uri', 'return', 'return_url',
        'returnurl', 'next', 'destination', 'dest', 'target', 'continue', 'redir',
        'callback', 'goto', 'link', 'forward', 'out', 'view', 'to', 'r', 'ret'
    ]
    
    def __init__(self, timeout: int = 10):
        """
        Initialize Open Redirect Scanner
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.max_redirects = 5
    
    def scan_url(self, url: str, params: Dict[str, str] = None, method: str = "GET") -> List[Dict[str, Any]]:
        """
        Scan URL for open redirect vulnerabilities
        
        Args:
            url: Target URL
            params: URL parameters or POST data
            method: HTTP method
            
        Returns:
            List of detected open redirect vulnerabilities
        """
        vulnerabilities = []
        
        if not params:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if not params:
            logger.warning(f"No parameters found for {url}")
            return vulnerabilities
        
        logger.info(f"Testing open redirect on {url} with {len(params)} parameters")
        
        # Test each parameter
        for param_name in params.keys():
            # Focus on likely redirect parameters
            if any(redirect_name in param_name.lower() for redirect_name in self.REDIRECT_PARAMS):
                logger.info(f"Testing potential redirect parameter: {param_name}")
            
            vulns = self._test_open_redirect(url, params, param_name, method)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _test_open_redirect(self, url: str, params: Dict, param_name: str, method: str) -> List[Dict[str, Any]]:
        """Test parameter for open redirect"""
        vulnerabilities = []
        
        for payload in self.REDIRECT_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                if method.upper() == "POST":
                    response = self.session.post(
                        url, 
                        data=test_params, 
                        timeout=self.timeout, 
                        verify=False,
                        allow_redirects=True
                    )
                else:
                    response = self.session.get(
                        url, 
                        params=test_params, 
                        timeout=self.timeout, 
                        verify=False,
                        allow_redirects=True
                    )
                
                # Check if redirected to external domain
                if self._is_external_redirect(url, response, payload):
                    vulnerabilities.append({
                        'type': 'Open Redirect',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'evidence': f"Redirected to: {response.url}",
                        'final_url': response.url,
                        'status_code': response.status_code,
                        'response_snippet': response.text[:500]
                    })
                    logger.warning(f"✗ Open Redirect detected in {param_name}")
                    break  # Found vulnerability, move to next parameter
                
                # Check Location header even without following redirects
                if 'Location' in response.headers:
                    location = response.headers['Location']
                    if self._is_suspicious_redirect(location, payload):
                        vulnerabilities.append({
                            'type': 'Open Redirect',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': f"Location header: {location}",
                            'final_url': location,
                            'status_code': response.status_code,
                            'response_snippet': response.text[:500]
                        })
                        logger.warning(f"✗ Open Redirect detected in {param_name}")
                        break
            
            except Exception as e:
                logger.debug(f"Error testing open redirect: {e}")
        
        return vulnerabilities
    
    def _is_external_redirect(self, original_url: str, response: requests.Response, payload: str) -> bool:
        """
        Check if response redirected to external domain
        
        Args:
            original_url: Original request URL
            response: HTTP response
            payload: Test payload
            
        Returns:
            bool: True if redirected externally
        """
        original_domain = urllib.parse.urlparse(original_url).netloc
        final_domain = urllib.parse.urlparse(response.url).netloc
        
        # Check if redirected to different domain
        if original_domain != final_domain:
            # Check if it matches our test domain
            if 'evil.com' in final_domain or 'google.com' in final_domain:
                return True
        
        return False
    
    def _is_suspicious_redirect(self, location: str, payload: str) -> bool:
        """
        Check if Location header contains suspicious redirect
        
        Args:
            location: Location header value
            payload: Original payload
            
        Returns:
            bool: True if suspicious
        """
        # Check for external domains
        if 'evil.com' in location.lower():
            return True
        
        # Check for protocol handlers
        if location.lower().startswith('javascript:'):
            return True
        if location.lower().startswith('data:'):
            return True
        
        # Check for open redirect patterns
        if location.startswith('//'):
            parsed = urllib.parse.urlparse('http:' + location)
            if parsed.netloc and 'evil.com' in parsed.netloc:
                return True
        
        return False


# Example usage
if __name__ == "__main__":
    scanner = OpenRedirectScanner()
    
    test_url = "https://example.com/redirect"
    test_params = {"url": "https://example.com"}
    
    vulnerabilities = scanner.scan_url(test_url, test_params)
    
    print(f"\nFound {len(vulnerabilities)} open redirect vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['type']} in parameter '{vuln['parameter']}'")
