"""
Security Headers Scanner Module
Analyzes HTTP security headers and identifies misconfigurations
"""

import requests
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class HeaderScanner:
    """
    HTTP Security Headers analyzer
    Checks for missing or misconfigured security headers
    """
    
    # Security headers to check
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'HTTP Strict Transport Security (HSTS)',
            'risk': 'Medium',
            'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'description': 'Content Security Policy (CSP)',
            'risk': 'High',
            'recommendation': 'Implement a strict Content Security Policy to prevent XSS attacks'
        },
        'X-Frame-Options': {
            'description': 'Clickjacking Protection',
            'risk': 'Medium',
            'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'description': 'MIME Type Sniffing Protection',
            'risk': 'Low',
            'recommendation': 'Add: X-Content-Type-Options: nosniff'
        },
        'X-XSS-Protection': {
            'description': 'XSS Filter',
            'risk': 'Low',
            'recommendation': 'Add: X-XSS-Protection: 1; mode=block'
        },
        'Referrer-Policy': {
            'description': 'Referrer Policy',
            'risk': 'Low',
            'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'description': 'Feature Policy / Permissions Policy',
            'risk': 'Low',
            'recommendation': 'Implement Permissions-Policy to restrict browser features'
        }
    }
    
    # Insecure headers to detect
    INSECURE_HEADERS = [
        'X-Powered-By',
        'Server',
        'X-AspNet-Version',
        'X-AspNetMvc-Version'
    ]
    
    def __init__(self, timeout: int = 10):
        """
        Initialize Header Scanner
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan(self, url: str) -> Dict[str, Any]:
        """
        Scan URL for security header issues
        
        Args:
            url: Target URL
            
        Returns:
            Dict with header analysis results
        """
        logger.info(f"Scanning security headers for: {url}")
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            missing_headers = []
            present_headers = []
            misconfigured_headers = []
            information_disclosure = []
            
            # Check for missing security headers
            for header, info in self.SECURITY_HEADERS.items():
                if header not in headers:
                    missing_headers.append({
                        'header': header,
                        'description': info['description'],
                        'risk': info['risk'],
                        'recommendation': info['recommendation']
                    })
                else:
                    present_headers.append({
                        'header': header,
                        'value': headers[header],
                        'description': info['description']
                    })
                    
                    # Check for misconfigurations
                    misconfig = self._check_misconfiguration(header, headers[header])
                    if misconfig:
                        misconfigured_headers.append(misconfig)
            
            # Check for information disclosure headers
            for header in self.INSECURE_HEADERS:
                if header in headers:
                    information_disclosure.append({
                        'header': header,
                        'value': headers[header],
                        'risk': 'Low',
                        'recommendation': f'Remove or obscure {header} header'
                    })
            
            # Check CORS configuration
            cors_issues = self._check_cors(headers)
            
            return {
                'url': url,
                'missing_headers': missing_headers,
                'present_headers': present_headers,
                'misconfigured_headers': misconfigured_headers,
                'information_disclosure': information_disclosure,
                'cors_issues': cors_issues,
                'total_issues': len(missing_headers) + len(misconfigured_headers) + len(information_disclosure) + len(cors_issues)
            }
        
        except Exception as e:
            logger.error(f"Error scanning headers: {e}")
            return {'error': str(e)}
    
    def _check_misconfiguration(self, header: str, value: str) -> Dict[str, Any]:
        """Check if security header is misconfigured"""
        
        if header == 'X-Frame-Options':
            if value.upper() not in ['DENY', 'SAMEORIGIN']:
                return {
                    'header': header,
                    'value': value,
                    'issue': 'Weak X-Frame-Options value',
                    'risk': 'Medium',
                    'recommendation': 'Use DENY or SAMEORIGIN'
                }
        
        elif header == 'Strict-Transport-Security':
            if 'max-age' not in value.lower():
                return {
                    'header': header,
                    'value': value,
                    'issue': 'Missing max-age directive',
                    'risk': 'Medium',
                    'recommendation': 'Include max-age directive with value >= 31536000'
                }
            
            # Check for short max-age
            import re
            match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
            if match and int(match.group(1)) < 31536000:
                return {
                    'header': header,
                    'value': value,
                    'issue': 'HSTS max-age too short',
                    'risk': 'Low',
                    'recommendation': 'Increase max-age to at least 31536000 (1 year)'
                }
        
        elif header == 'Content-Security-Policy':
            if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                return {
                    'header': header,
                    'value': value,
                    'issue': 'CSP allows unsafe-inline or unsafe-eval',
                    'risk': 'High',
                    'recommendation': 'Remove unsafe-inline and unsafe-eval directives'
                }
        
        return None
    
    def _check_cors(self, headers: Dict) -> List[Dict[str, Any]]:
        """Check CORS configuration for security issues"""
        issues = []
        
        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', '')
        
        # Wildcard with credentials
        if acao == '*' and acac.lower() == 'true':
            issues.append({
                'type': 'CORS Misconfiguration',
                'issue': 'Wildcard origin with credentials enabled',
                'risk': 'Critical',
                'recommendation': 'Do not use wildcard (*) with credentials enabled',
                'evidence': f'Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}'
            })
        
        # Overly permissive wildcard
        elif acao == '*':
            issues.append({
                'type': 'CORS Misconfiguration',
                'issue': 'Wildcard origin allows any domain',
                'risk': 'Medium',
                'recommendation': 'Specify allowed origins explicitly',
                'evidence': f'Access-Control-Allow-Origin: {acao}'
            })
        
        # Null origin
        elif acao == 'null':
            issues.append({
                'type': 'CORS Misconfiguration',
                'issue': 'Null origin allowed',
                'risk': 'High',
                'recommendation': 'Do not allow null origin',
                'evidence': f'Access-Control-Allow-Origin: {acao}'
            })
        
        return issues


# Example usage
if __name__ == "__main__":
    scanner = HeaderScanner()
    
    result = scanner.scan("https://example.com")
    
    print(f"\nHeader Scan Results:")
    print(f"  Missing Headers: {len(result.get('missing_headers', []))}")
    print(f"  Misconfigured Headers: {len(result.get('misconfigured_headers', []))}")
    print(f"  Information Disclosure: {len(result.get('information_disclosure', []))}")
    print(f"  CORS Issues: {len(result.get('cors_issues', []))}")
