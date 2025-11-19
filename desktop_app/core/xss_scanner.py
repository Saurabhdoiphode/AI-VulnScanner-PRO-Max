"""
Cross-Site Scripting (XSS) Scanner Module
Detects reflective, stored, and DOM-based XSS vulnerabilities
"""

import requests
import urllib.parse
from typing import List, Dict, Any
import re
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class XSSScanner:
    """
    Advanced XSS vulnerability scanner
    Tests for reflective, stored, and DOM-based XSS
    """
    
    # XSS test payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "\"><img src=x onerror=alert('XSS')>",
        "'><svg/onload=alert('XSS')>",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=\"javascript:alert('XSS')\">",
        "<object data=\"javascript:alert('XSS')\">",
        "<embed src=\"javascript:alert('XSS')\">",
    ]
    
    # DOM-based XSS patterns
    DOM_XSS_PATTERNS = [
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"document\.location",
        r"document\.URL",
        r"document\.referrer",
        r"window\.location",
        r"eval\s*\(",
        r"setTimeout\s*\(",
        r"setInterval\s*\("
    ]
    
    def __init__(self, timeout: int = 10):
        """
        Initialize XSS Scanner
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan_url(self, url: str, params: Dict[str, str] = None, method: str = "GET") -> List[Dict[str, Any]]:
        """
        Scan URL for XSS vulnerabilities
        
        Args:
            url: Target URL
            params: URL parameters or POST data
            method: HTTP method
            
        Returns:
            List of detected XSS vulnerabilities
        """
        vulnerabilities = []
        
        if not params:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if not params:
            logger.warning(f"No parameters found for {url}")
            return vulnerabilities
        
        logger.info(f"Testing XSS on {url} with {len(params)} parameters")
        
        # Test reflective XSS on each parameter
        for param_name in params.keys():
            vulns = self._test_reflective_xss(url, params, param_name, method)
            vulnerabilities.extend(vulns)
        
        # Test DOM-based XSS
        dom_vulns = self._test_dom_xss(url, params, method)
        vulnerabilities.extend(dom_vulns)
        
        return vulnerabilities
    
    def _test_reflective_xss(self, url: str, params: Dict, param_name: str, method: str) -> List[Dict[str, Any]]:
        """Test for reflective XSS vulnerabilities"""
        vulnerabilities = []
        
        for payload in self.XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                if method.upper() == "POST":
                    response = self.session.post(url, data=test_params, timeout=self.timeout, verify=False)
                else:
                    response = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                
                # Check if payload is reflected in response
                if self._is_xss_reflected(response.text, payload):
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS) - Reflective',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'evidence': self._extract_xss_context(response.text, payload),
                        'status_code': response.status_code,
                        'response_snippet': response.text[:500]
                    })
                    logger.warning(f"✗ Reflective XSS detected in {param_name}")
                    break  # Found vulnerability, move to next parameter
            
            except Exception as e:
                logger.debug(f"Error testing XSS payload: {e}")
        
        return vulnerabilities
    
    def _test_dom_xss(self, url: str, params: Dict, method: str) -> List[Dict[str, Any]]:
        """Test for DOM-based XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            if method.upper() == "POST":
                response = self.session.post(url, data=params, timeout=self.timeout, verify=False)
            else:
                response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
            
            # Parse JavaScript code
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script')
            
            for script in scripts:
                script_content = script.string if script.string else ""
                
                # Check for dangerous DOM manipulation patterns
                for pattern in self.DOM_XSS_PATTERNS:
                    if re.search(pattern, script_content, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS) - DOM-Based',
                            'url': url,
                            'parameter': 'N/A (DOM-based)',
                            'payload': 'N/A',
                            'method': method,
                            'evidence': self._extract_pattern_context(script_content, pattern),
                            'status_code': response.status_code,
                            'response_snippet': script_content[:300]
                        })
                        logger.warning(f"✗ DOM-based XSS pattern detected: {pattern}")
                        break
        
        except Exception as e:
            logger.debug(f"Error testing DOM XSS: {e}")
        
        return vulnerabilities
    
    def _is_xss_reflected(self, response_text: str, payload: str) -> bool:
        """
        Check if XSS payload is reflected in response
        
        Args:
            response_text: HTTP response body
            payload: XSS payload
            
        Returns:
            bool: True if payload is reflected unsafely
        """
        # Check for exact match
        if payload in response_text:
            return True
        
        # Check for URL-encoded version
        encoded_payload = urllib.parse.quote(payload)
        if encoded_payload in response_text:
            return True
        
        # Check for HTML-encoded version
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if html_encoded not in response_text and payload in response_text:
            # Payload is reflected without encoding - vulnerable!
            return True
        
        # Check for partial matches (script tags, event handlers)
        dangerous_patterns = [
            r"<script[^>]*>",
            r"onerror\s*=",
            r"onload\s*=",
            r"onfocus\s*=",
            r"javascript:",
            r"<iframe",
            r"<object",
            r"<embed"
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Check if this pattern came from our payload
                payload_lower = payload.lower()
                if any(keyword in payload_lower for keyword in ['script', 'onerror', 'onload', 'iframe', 'javascript']):
                    return True
        
        return False
    
    def _extract_xss_context(self, response_text: str, payload: str) -> str:
        """Extract context around XSS payload in response"""
        try:
            index = response_text.find(payload)
            if index != -1:
                start = max(0, index - 100)
                end = min(len(response_text), index + len(payload) + 100)
                return response_text[start:end]
        except:
            pass
        return "XSS payload reflected in response"
    
    def _extract_pattern_context(self, script_content: str, pattern: str) -> str:
        """Extract context around dangerous DOM pattern"""
        try:
            match = re.search(pattern, script_content, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(script_content), match.end() + 50)
                return script_content[start:end]
        except:
            pass
        return f"Dangerous pattern found: {pattern}"
    
    def scan_for_stored_xss(self, url: str, input_params: Dict, check_url: str) -> List[Dict[str, Any]]:
        """
        Test for stored XSS vulnerabilities
        
        Args:
            url: URL where payload is submitted
            input_params: Parameters to submit
            check_url: URL where stored data is displayed
            
        Returns:
            List of stored XSS vulnerabilities
        """
        vulnerabilities = []
        
        # Generate unique payload for tracking
        unique_id = f"XSS_{int(time.time())}"
        payload = f"<script>alert('{unique_id}')</script>"
        
        try:
            # Submit payload
            test_params = input_params.copy()
            for param in test_params.keys():
                test_params[param] = payload
                
                response = self.session.post(url, data=test_params, timeout=self.timeout, verify=False)
                
                # Check if payload is stored and reflected
                check_response = self.session.get(check_url, timeout=self.timeout, verify=False)
                
                if unique_id in check_response.text and '<script>' in check_response.text:
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS) - Stored',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'method': 'POST',
                        'evidence': f"Payload stored and reflected on {check_url}",
                        'status_code': check_response.status_code,
                        'response_snippet': check_response.text[:500]
                    })
                    logger.warning(f"✗ Stored XSS detected in {param}")
        
        except Exception as e:
            logger.debug(f"Error testing stored XSS: {e}")
        
        return vulnerabilities


# Example usage
if __name__ == "__main__":
    scanner = XSSScanner()
    
    test_url = "https://example.com/search"
    test_params = {"q": "test"}
    
    vulnerabilities = scanner.scan_url(test_url, test_params)
    
    print(f"\nFound {len(vulnerabilities)} XSS vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['type']} in parameter '{vuln['parameter']}'")
