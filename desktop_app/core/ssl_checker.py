"""
SSL/TLS Security Checker Module
Analyzes SSL/TLS configuration and certificates
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class SSLChecker:
    """
    SSL/TLS security analyzer
    Checks for weak ciphers, protocol versions, and certificate issues
    """
    
    # Weak/deprecated protocols
    WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
    
    # Weak cipher suites
    WEAK_CIPHERS = [
        'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'PSK', 'SRP',
        'CAMELLIA', 'SEED', 'IDEA', 'AESCCM', 'anon'
    ]
    
    def __init__(self, timeout: int = 10):
        """
        Initialize SSL Checker
        
        Args:
            timeout: Connection timeout
        """
        self.timeout = timeout
    
    def check_ssl(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Comprehensive SSL/TLS security check
        
        Args:
            hostname: Target hostname
            port: SSL/TLS port (default 443)
            
        Returns:
            Dict with SSL analysis results
        """
        logger.info(f"Checking SSL/TLS for {hostname}:{port}")
        
        result = {
            'hostname': hostname,
            'port': port,
            'certificate': {},
            'protocols': {},
            'vulnerabilities': [],
            'issues': []
        }
        
        try:
            # Get certificate information
            cert_info = self._get_certificate_info(hostname, port)
            result['certificate'] = cert_info
            
            # Check certificate validity
            cert_issues = self._check_certificate_issues(cert_info)
            result['issues'].extend(cert_issues)
            
            # Check supported protocols
            protocols = self._check_protocols(hostname, port)
            result['protocols'] = protocols
            
            # Check for weak protocols
            weak_protocols = self._check_weak_protocols(protocols)
            if weak_protocols:
                result['vulnerabilities'].extend(weak_protocols)
            
            # Check cipher suites
            cipher_info = self._check_ciphers(hostname, port)
            result['ciphers'] = cipher_info
            
            # Check for weak ciphers
            weak_ciphers = self._check_weak_ciphers(cipher_info)
            if weak_ciphers:
                result['vulnerabilities'].extend(weak_ciphers)
            
            result['total_issues'] = len(result['issues']) + len(result['vulnerabilities'])
            
        except Exception as e:
            logger.error(f"SSL check error: {e}")
            result['error'] = str(e)
        
        return result
    
    def _get_certificate_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """Get SSL certificate information"""
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
                
                # Parse certificate details
                cert_info = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'san': self._get_san(cert),
                    'protocol': protocol,
                    'cipher': cipher[0] if cipher else None,
                    'cipher_bits': cipher[2] if cipher and len(cipher) > 2 else None
                }
                
                return cert_info
    
    def _get_san(self, cert: Dict) -> List[str]:
        """Extract Subject Alternative Names from certificate"""
        san = []
        
        if 'subjectAltName' in cert:
            for item in cert['subjectAltName']:
                if item[0] == 'DNS':
                    san.append(item[1])
        
        return san
    
    def _check_certificate_issues(self, cert_info: Dict) -> List[Dict[str, Any]]:
        """Check for certificate-related issues"""
        issues = []
        
        # Check expiration
        try:
            not_after = cert_info.get('not_after')
            if not_after:
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.now()).days
                
                if days_until_expiry < 0:
                    issues.append({
                        'type': 'Certificate Expired',
                        'severity': 'Critical',
                        'details': f'Certificate expired {abs(days_until_expiry)} days ago',
                        'recommendation': 'Renew SSL certificate immediately'
                    })
                elif days_until_expiry < 30:
                    issues.append({
                        'type': 'Certificate Expiring Soon',
                        'severity': 'High',
                        'details': f'Certificate expires in {days_until_expiry} days',
                        'recommendation': 'Renew SSL certificate'
                    })
        except Exception as e:
            logger.debug(f"Error checking expiration: {e}")
        
        # Check for self-signed certificate
        subject = cert_info.get('subject', {})
        issuer = cert_info.get('issuer', {})
        
        if subject == issuer:
            issues.append({
                'type': 'Self-Signed Certificate',
                'severity': 'Medium',
                'details': 'Certificate is self-signed',
                'recommendation': 'Use certificate from trusted CA'
            })
        
        return issues
    
    def _check_protocols(self, hostname: str, port: int) -> Dict[str, bool]:
        """Check which SSL/TLS protocols are supported"""
        protocols = {}
        
        protocol_versions = [
            ('SSLv2', ssl.PROTOCOL_SSLv23),
            ('SSLv3', ssl.PROTOCOL_SSLv23),
            ('TLSv1', ssl.PROTOCOL_TLSv1) if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1) if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2) if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            ('TLSv1.3', ssl.PROTOCOL_TLS) if hasattr(ssl, 'PROTOCOL_TLS') else None,
        ]
        
        for name, protocol in protocol_versions:
            if protocol is None:
                continue
            
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock) as ssock:
                        protocols[name] = True
            except:
                protocols[name] = False
        
        return protocols
    
    def _check_weak_protocols(self, protocols: Dict[str, bool]) -> List[Dict[str, Any]]:
        """Check for weak/deprecated protocols"""
        vulnerabilities = []
        
        for protocol in self.WEAK_PROTOCOLS:
            if protocols.get(protocol, False):
                vulnerabilities.append({
                    'type': f'Weak Protocol: {protocol}',
                    'severity': 'High' if protocol in ['SSLv2', 'SSLv3'] else 'Medium',
                    'details': f'{protocol} is deprecated and insecure',
                    'recommendation': f'Disable {protocol} and use TLS 1.2 or higher'
                })
        
        return vulnerabilities
    
    def _check_ciphers(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check supported cipher suites"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    return {
                        'negotiated_cipher': cipher[0] if cipher else None,
                        'protocol': cipher[1] if cipher and len(cipher) > 1 else None,
                        'bits': cipher[2] if cipher and len(cipher) > 2 else None
                    }
        except Exception as e:
            logger.debug(f"Error checking ciphers: {e}")
            return {}
    
    def _check_weak_ciphers(self, cipher_info: Dict) -> List[Dict[str, Any]]:
        """Check for weak cipher suites"""
        vulnerabilities = []
        
        cipher = cipher_info.get('negotiated_cipher', '')
        
        for weak in self.WEAK_CIPHERS:
            if weak.upper() in cipher.upper():
                vulnerabilities.append({
                    'type': f'Weak Cipher Suite',
                    'severity': 'High',
                    'details': f'Weak cipher detected: {cipher}',
                    'recommendation': 'Disable weak ciphers and use strong cipher suites (e.g., AES-GCM)'
                })
                break
        
        # Check key size
        bits = cipher_info.get('bits')
        if bits and bits < 128:
            vulnerabilities.append({
                'type': 'Insufficient Key Length',
                'severity': 'High',
                'details': f'Cipher uses only {bits} bits',
                'recommendation': 'Use ciphers with at least 128-bit keys'
            })
        
        return vulnerabilities


# Example usage
if __name__ == "__main__":
    checker = SSLChecker()
    
    result = checker.check_ssl("example.com", 443)
    
    print(f"\nSSL Check Results:")
    print(f"  Total Issues: {result.get('total_issues', 0)}")
    print(f"  Certificate Valid: {result.get('certificate', {}).get('not_after')}")
