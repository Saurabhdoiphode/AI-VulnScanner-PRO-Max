"""
AI-VulnScanner PRO Max - Main Scanner Orchestrator (Shared Core)
Coordinates all scanning modules and AI analysis
Used by both Desktop GUI and Web Application
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from typing import Dict, List, Any, Optional, Callable
import time
from datetime import datetime

# Import original scanners from core/
from core.crawler import WebCrawler
from core.sql_injection import SQLInjectionScanner
from core.xss_scanner import XSSScanner
from core.ssti_scanner import SSTIScanner
from core.cmd_injection import CommandInjectionScanner
from core.path_traversal import PathTraversalScanner
from core.open_redirect import OpenRedirectScanner
from core.header_scanner import HeaderScanner
from core.directory_finder import DirectoryFinder
from core.tech_fingerprint import TechFingerprint
from core.port_scanner import PortScanner
from core.ssl_checker import SSLChecker
from core.osint import OSINTScanner

# Import new scanners
from shared_core.file_upload_test import FileUploadTester
from shared_core.ai_engine import AIEngine

class VulnerabilityScanner:
    """
    Main orchestrator for all vulnerability scanning operations
    Integrates: Web scans, Network scans, OSINT, AI analysis
    """
    
    def __init__(self, 
                 ai_enabled: bool = True,
                 ai_model: str = "llama3",
                 progress_callback: Optional[Callable] = None):
        """
        Initialize vulnerability scanner
        
        Args:
            ai_enabled: Enable AI-powered analysis
            ai_model: AI model to use
            progress_callback: Function to call with progress updates
        """
        self.ai_enabled = ai_enabled
        self.progress_callback = progress_callback
        self.logger = logging.getLogger(__name__)
        
        # Initialize AI engine
        if ai_enabled:
            try:
                self.ai_engine = AIEngine(model=ai_model)
                if not self.ai_engine.check_availability():
                    self.logger.warning("AI service unavailable, using fallback analysis")
                    self.ai_enabled = False
            except Exception as e:
                self.logger.error(f"AI initialization failed: {e}")
                self.ai_enabled = False
        else:
            self.ai_engine = None
        
        # Initialize all scanners
        self.web_crawler = WebCrawler()
        self.sql_scanner = SQLInjectionScanner()
        self.xss_scanner = XSSScanner()
        self.ssti_scanner = SSTIScanner()
        self.cmd_scanner = CommandInjectionScanner()
        self.path_scanner = PathTraversalScanner()
        self.redirect_scanner = OpenRedirectScanner()
        self.header_scanner = HeaderScanner()
        self.directory_finder = DirectoryFinder()
        self.tech_fingerprint = TechFingerprint()
        self.port_scanner = PortScanner()
        self.ssl_checker = SSLChecker()
        self.osint_scanner = OSINTScanner()
        self.file_upload_tester = FileUploadTester()
        
        # Scan results storage
        self.results = {
            'scan_id': None,
            'target': None,
            'start_time': None,
            'end_time': None,
            'duration': None,
            'vulnerabilities': [],
            'technologies': [],
            'open_ports': [],
            'ssl_info': {},
            'osint_data': {},
            'endpoints': [],
            'forms': [],
            'statistics': {}
        }
    
    def full_scan(self, 
                 target: str,
                 scan_types: List[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive vulnerability scan
        
        Args:
            target: Target URL or IP address
            scan_types: List of scan types to perform
                       ['web', 'network', 'osint', 'ai']
                       
        Returns:
            Complete scan results dictionary
        """
        self.results['scan_id'] = f"scan_{int(time.time())}"
        self.results['target'] = target
        self.results['start_time'] = datetime.now().isoformat()
        
        if scan_types is None:
            scan_types = ['web', 'network', 'osint', 'ai']
        
        self._update_progress("Starting comprehensive scan...", 0)
        
        try:
            # Phase 1: Reconnaissance (10%)
            if 'web' in scan_types or 'osint' in scan_types:
                self._update_progress("Phase 1: Reconnaissance", 10)
                self._reconnaissance_phase(target)
            
            # Phase 2: Web Vulnerability Scanning (40%)
            if 'web' in scan_types:
                self._update_progress("Phase 2: Web Vulnerability Scanning", 20)
                self._web_scan_phase(target)
            
            # Phase 3: Network Scanning (20%)
            if 'network' in scan_types:
                self._update_progress("Phase 3: Network Scanning", 60)
                self._network_scan_phase(target)
            
            # Phase 4: OSINT Gathering (10%)
            if 'osint' in scan_types:
                self._update_progress("Phase 4: OSINT Gathering", 80)
                self._osint_phase(target)
            
            # Phase 5: AI Analysis (10%)
            if 'ai' in scan_types and self.ai_enabled:
                self._update_progress("Phase 5: AI Analysis", 90)
                self._ai_analysis_phase()
            
            # Finalize results
            self._update_progress("Generating report...", 95)
            self._finalize_results()
            
            self._update_progress("Scan complete!", 100)
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.results['error'] = str(e)
        
        return self.results
    
    def web_scan_only(self, target: str) -> Dict[str, Any]:
        """Quick web vulnerability scan"""
        return self.full_scan(target, scan_types=['web', 'ai'])
    
    def network_scan_only(self, target: str) -> Dict[str, Any]:
        """Quick network scan"""
        return self.full_scan(target, scan_types=['network'])
    
    def osint_scan_only(self, target: str) -> Dict[str, Any]:
        """Quick OSINT gathering"""
        return self.full_scan(target, scan_types=['osint'])
    
    def _reconnaissance_phase(self, target: str):
        """Phase 1: Reconnaissance and fingerprinting"""
        self.logger.info("Starting reconnaissance phase")
        
        # Crawl website
        self._update_progress("Crawling website...", 12)
        try:
            crawl_results = self.web_crawler.crawl(target)
            self.results['endpoints'] = crawl_results.get('urls', [target])
            self.results['forms'] = crawl_results.get('forms', [])
        except Exception as e:
            self.logger.error(f"Crawl failed: {e}")
            self.results['endpoints'] = [target]
            self.results['forms'] = []
        
        # Technology fingerprinting
        self._update_progress("Fingerprinting technologies...", 15)
        try:
            tech_info = self.tech_fingerprint.fingerprint(target)
            self.results['technologies'] = tech_info.get('technologies', [])
            self.results['waf_detected'] = tech_info.get('waf_detected', False)
        except Exception as e:
            self.logger.error(f"Fingerprinting failed: {e}")
            self.results['technologies'] = []
            self.results['waf_detected'] = False
        
        self.logger.info(f"Found {len(self.results['endpoints'])} URLs, {len(self.results['forms'])} forms")
    
    def _web_scan_phase(self, target: str):
        """Phase 2: Web vulnerability scanning"""
        self.logger.info("Starting web vulnerability scan")
        
        endpoints = self.results.get('endpoints', [target])
        forms = self.results.get('forms', [])
        
        # Prepare test targets with parameters
        test_urls = []
        for endpoint in endpoints:
            # Add parameter for testing
            if '?' not in endpoint:
                test_urls.append(f"{endpoint}?id=1")
                test_urls.append(f"{endpoint}?name=test")
            else:
                test_urls.append(endpoint)
        
        # Add form actions
        for form in forms:
            if form.get('action'):
                test_urls.append(form['action'])
        
        # Ensure we have at least the target
        if not test_urls:
            test_urls = [f"{target}?id=1", f"{target}?page=home"]
        
        test_urls = test_urls[:20]  # Limit for performance
        
        # SQL Injection (5%)
        self._update_progress("Testing for SQL injection...", 25)
        for endpoint in test_urls[:10]:
            try:
                vulns = self.sql_scanner.scan_url(endpoint)
                self.results['vulnerabilities'].extend(vulns)
            except Exception as e:
                self.logger.debug(f"SQL scan error on {endpoint}: {e}")
            time.sleep(0.2)
        
        # Test forms for SQL injection
        for form in forms[:5]:
            try:
                if form.get('inputs'):
                    params = {inp['name']: 'test' for inp in form['inputs'] if inp.get('name')}
                    vulns = self.sql_scanner.scan_url(form.get('action', target), params, form.get('method', 'GET'))
                    self.results['vulnerabilities'].extend(vulns)
            except Exception as e:
                self.logger.debug(f"SQL form scan error: {e}")
        
        # XSS (5%)
        self._update_progress("Testing for XSS...", 30)
        for endpoint in test_urls[:10]:
            try:
                vulns = self.xss_scanner.scan_url(endpoint)
                self.results['vulnerabilities'].extend(vulns)
            except Exception as e:
                self.logger.debug(f"XSS scan error on {endpoint}: {e}")
            time.sleep(0.2)
        
        # Test forms for XSS
        for form in forms[:5]:
            try:
                if form.get('inputs'):
                    params = {inp['name']: 'test' for inp in form['inputs'] if inp.get('name')}
                    vulns = self.xss_scanner.scan_url(form.get('action', target), params, form.get('method', 'GET'))
                    self.results['vulnerabilities'].extend(vulns)
            except Exception as e:
                self.logger.debug(f"XSS form scan error: {e}")
        
        # SSTI (5%)
        self._update_progress("Testing for SSTI...", 35)
        for endpoint in test_urls[:8]:
            try:
                vulns = self.ssti_scanner.scan_url(endpoint)
                self.results['vulnerabilities'].extend(vulns)
            except Exception as e:
                self.logger.debug(f"SSTI scan error on {endpoint}: {e}")
            time.sleep(0.2)
        
        # Command Injection (5%)
        self._update_progress("Testing for command injection...", 40)
        for endpoint in test_urls[:8]:
            try:
                vulns = self.cmd_scanner.scan_url(endpoint)
                self.results['vulnerabilities'].extend(vulns)
            except Exception as e:
                self.logger.debug(f"CMD scan error on {endpoint}: {e}")
            time.sleep(0.2)
        
        # Path Traversal (5%)
        self._update_progress("Testing for path traversal...", 45)
        for endpoint in test_urls[:10]:
            try:
                vulns = self.path_scanner.scan_url(endpoint)
                self.results['vulnerabilities'].extend(vulns)
            except Exception as e:
                self.logger.debug(f"Path traversal scan error on {endpoint}: {e}")
            time.sleep(0.2)
        
        # Open Redirect (3%)
        self._update_progress("Testing for open redirects...", 48)
        for endpoint in test_urls[:10]:
            try:
                vulns = self.redirect_scanner.scan_url(endpoint)
                self.results['vulnerabilities'].extend(vulns)
            except Exception as e:
                self.logger.debug(f"Redirect scan error on {endpoint}: {e}")
            time.sleep(0.2)
        
        # File Upload (3%)
        self._update_progress("Testing file uploads...", 51)
        if forms:
            upload_vulns = self.file_upload_tester.scan_upload_forms(target, forms)
            self.results['vulnerabilities'].extend(upload_vulns)
        
        # Security Headers (2%)
        self._update_progress("Analyzing security headers...", 53)
        header_results = self.header_scanner.scan(target)
        self.results['vulnerabilities'].extend(header_results.get('vulnerabilities', []))
        self.results['headers'] = header_results.get('headers', {})
        
        # Directory/File Discovery (5%)
        self._update_progress("Searching for sensitive files...", 55)
        dir_results = self.directory_finder.scan(target)
        
        # Convert found files to vulnerabilities
        for found_file in dir_results.get('sensitive_files', []):
            self.results['vulnerabilities'].append({
                'type': 'Sensitive File Exposure',
                'url': found_file['url'],
                'severity': found_file.get('risk', 'Medium'),
                'description': f"Sensitive file exposed: {found_file['path']}",
                'status_code': found_file['status_code'],
                'evidence': f"File size: {found_file['size']} bytes"
            })
        
        # Convert found directories to informational findings
        for found_dir in dir_results.get('directories', []):
            if found_dir['path'] in ['admin', 'administrator', 'phpmyadmin', 'backup', 'config']:
                self.results['vulnerabilities'].append({
                    'type': 'Sensitive Directory Exposure',
                    'url': found_dir['url'],
                    'severity': 'Low',
                    'description': f"Potentially sensitive directory found: {found_dir['path']}",
                    'status_code': found_dir['status_code']
                })
        
        self.logger.info(f"Web scan complete: {len(self.results['vulnerabilities'])} issues found")
    
    def _network_scan_phase(self, target: str):
        """Phase 3: Network scanning"""
        self.logger.info("Starting network scan")
        
        # Extract hostname from URL
        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        
        # Port Scan (15%)
        self._update_progress("Scanning ports...", 65)
        try:
            # Use common ports (not passing ports parameter uses COMMON_PORTS)
            port_results = self.port_scanner.scan_host(hostname)
            self.results['open_ports'] = port_results.get('open_ports', [])
        except Exception as e:
            self.logger.error(f"Port scan failed: {e}")
            self.results['open_ports'] = []
        
        # SSL/TLS Analysis (5%)
        self._update_progress("Analyzing SSL/TLS...", 75)
        if parsed.scheme == 'https':
            ssl_results = self.ssl_checker.check_ssl(hostname)
            self.results['ssl_info'] = ssl_results
            
            # Add SSL vulnerabilities
            if ssl_results.get('vulnerabilities'):
                self.results['vulnerabilities'].extend(ssl_results['vulnerabilities'])
        
        self.logger.info(f"Network scan complete: {len(port_results)} open ports")
    
    def _osint_phase(self, target: str):
        """Phase 4: OSINT gathering"""
        self.logger.info("Starting OSINT gathering")
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = parsed.hostname or target
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        self._update_progress("Gathering OSINT data...", 85)
        osint_results = self.osint_scanner.gather_intelligence(domain)
        self.results['osint_data'] = osint_results
        
        self.logger.info("OSINT gathering complete")
    
    def _ai_analysis_phase(self):
        """Phase 5: AI-powered analysis"""
        if not self.ai_enabled or not self.ai_engine:
            self.logger.info("AI analysis skipped")
            return
        
        self.logger.info("Starting AI analysis")
        
        vulnerabilities = self.results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            self.logger.info("No vulnerabilities to analyze")
            return
        
        # Analyze each vulnerability
        analyzed_vulns = []
        total = len(vulnerabilities)
        
        for i, vuln in enumerate(vulnerabilities[:20]):  # Limit to first 20 for performance
            try:
                progress = 90 + (i / total * 5)  # 90-95%
                self._update_progress(f"AI analyzing vulnerability {i+1}/{total}...", progress)
                
                ai_analysis = self.ai_engine.analyze_vulnerability(
                    vuln,
                    context=f"Target: {self.results['target']}"
                )
                
                vuln['ai_analysis'] = ai_analysis
                analyzed_vulns.append(vuln)
                
                time.sleep(0.3)  # Rate limiting
                
            except Exception as e:
                self.logger.error(f"AI analysis failed for vulnerability: {e}")
                analyzed_vulns.append(vuln)
        
        # Generate executive summary
        try:
            summary = self.ai_engine.summarize_scan(self.results)
            self.results['ai_summary'] = summary
        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            self.results['ai_summary'] = "AI summary unavailable"
        
        self.logger.info("AI analysis complete")
    
    def _finalize_results(self):
        """Finalize scan results with statistics"""
        self.results['end_time'] = datetime.now().isoformat()
        
        # Calculate duration
        start = datetime.fromisoformat(self.results['start_time'])
        end = datetime.fromisoformat(self.results['end_time'])
        self.results['duration'] = str(end - start)
        
        # Calculate statistics
        vulns = self.results['vulnerabilities']
        
        self.results['statistics'] = {
            'total_vulnerabilities': len(vulns),
            'critical': sum(1 for v in vulns if v.get('severity') == 'Critical'),
            'high': sum(1 for v in vulns if v.get('severity') == 'High'),
            'medium': sum(1 for v in vulns if v.get('severity') == 'Medium'),
            'low': sum(1 for v in vulns if v.get('severity') == 'Low'),
            'total_endpoints': len(self.results.get('endpoints', [])),
            'total_forms': len(self.results.get('forms', [])),
            'open_ports': len(self.results.get('open_ports', [])),
            'technologies_detected': len(self.results.get('technologies', []))
        }
        
        # Add scan coverage information
        self.results['scan_coverage'] = {
            'urls_tested': len(self.results.get('endpoints', [])),
            'forms_analyzed': len(self.results.get('forms', [])),
            'ports_scanned': 'Common ports (21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443)',
            'tests_performed': [
                'SQL Injection',
                'Cross-Site Scripting (XSS)',
                'Server-Side Template Injection (SSTI)',
                'Command Injection',
                'Path Traversal',
                'Open Redirect',
                'File Upload Vulnerabilities',
                'Security Headers Analysis',
                'Sensitive File Discovery',
                'Directory Enumeration',
                'Port Scanning',
                'SSL/TLS Analysis',
                'OSINT Intelligence Gathering'
            ]
        }
        
        self.logger.info(f"Scan complete: {self.results['statistics']['total_vulnerabilities']} vulnerabilities found")
    
    def _update_progress(self, message: str, percent: int):
        """Update progress callback"""
        self.logger.info(f"[{percent}%] {message}")
        
        if self.progress_callback:
            try:
                self.progress_callback(message, percent)
            except Exception as e:
                self.logger.error(f"Progress callback failed: {e}")
