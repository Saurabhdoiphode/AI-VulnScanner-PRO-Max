"""
Main Scanner Orchestrator
Coordinates all scanning modules and AI analysis
"""

import logging
from typing import Dict, List, Any
import time
from datetime import datetime

# Import all scanner modules
from core.crawler import WebCrawler
from core.sql_injection import SQLInjectionScanner
from core.xss_scanner import XSSScanner
from core.ssti_scanner import SSTIScanner
from core.cmd_injection import CommandInjectionScanner
from core.path_traversal import PathTraversalScanner
from core.open_redirect import OpenRedirectScanner
from core.header_scanner import HeaderScanner
from core.directory_finder import DirectoryFinder
from core.port_scanner import PortScanner
from core.ssl_checker import SSLChecker
from core.osint import OSINTScanner
from core.tech_fingerprint import TechFingerprint
from core.ai_engine import AIEngine

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """
    Main vulnerability scanner orchestrator
    Coordinates all scanning modules and AI analysis
    """
    
    def __init__(self, ai_model: str = "llama3"):
        """
        Initialize scanner
        
        Args:
            ai_model: AI model to use for analysis
        """
        self.ai_engine = AIEngine(model_name=ai_model)
        
        # Initialize all scanners
        self.crawler = WebCrawler()
        self.sql_scanner = SQLInjectionScanner()
        self.xss_scanner = XSSScanner()
        self.ssti_scanner = SSTIScanner()
        self.cmd_scanner = CommandInjectionScanner()
        self.path_scanner = PathTraversalScanner()
        self.redirect_scanner = OpenRedirectScanner()
        self.header_scanner = HeaderScanner()
        self.dir_finder = DirectoryFinder()
        self.port_scanner = PortScanner()
        self.ssl_checker = SSLChecker()
        self.osint_scanner = OSINTScanner()
        self.tech_fingerprint = TechFingerprint()
        
        self.scan_results = {}
        self.vulnerabilities = []
    
    def full_scan(self, target: str, scan_options: Dict[str, bool] = None) -> Dict[str, Any]:
        """
        Perform comprehensive security scan
        
        Args:
            target: Target URL or IP
            scan_options: Dict of scan modules to enable/disable
            
        Returns:
            Complete scan results
        """
        logger.info(f"Starting full security scan on {target}")
        
        start_time = time.time()
        
        if scan_options is None:
            scan_options = {
                'web_scan': True,
                'network_scan': True,
                'osint_scan': True
            }
        
        results = {
            'target': target,
            'scan_start': datetime.now().isoformat(),
            'vulnerabilities': [],
            'summary': {}
        }
        
        try:
            # Phase 1: Reconnaissance
            logger.info("Phase 1: Reconnaissance")
            if scan_options.get('osint_scan', True):
                results['osint'] = self._run_osint(target)
            
            results['technology'] = self._run_tech_fingerprint(target)
            
            # Phase 2: Web Application Scanning
            if scan_options.get('web_scan', True):
                logger.info("Phase 2: Web Application Scanning")
                
                # Crawl website
                results['crawler'] = self._run_crawler(target)
                
                # Security headers
                results['headers'] = self._run_header_scan(target)
                
                # Directory enumeration
                results['directories'] = self._run_directory_scan(target)
                
                # Vulnerability scanning
                results['vulnerabilities'].extend(self._run_vulnerability_scans(target))
            
            # Phase 3: Network Scanning
            if scan_options.get('network_scan', True):
                logger.info("Phase 3: Network Scanning")
                results['network'] = self._run_network_scan(target)
            
            # Phase 4: AI Analysis
            logger.info("Phase 4: AI-Powered Analysis")
            results['ai_analysis'] = self._run_ai_analysis(results['vulnerabilities'])
            
            # Generate summary
            results['summary'] = self._generate_summary(results)
            results['scan_duration'] = time.time() - start_time
            results['scan_end'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            results['error'] = str(e)
        
        return results
    
    def _run_osint(self, target: str) -> Dict[str, Any]:
        """Run OSINT scan"""
        logger.info("Running OSINT scan...")
        try:
            return self.osint_scanner.gather_intelligence(target)
        except Exception as e:
            logger.error(f"OSINT error: {e}")
            return {'error': str(e)}
    
    def _run_tech_fingerprint(self, target: str) -> Dict[str, Any]:
        """Run technology fingerprinting"""
        logger.info("Running technology fingerprinting...")
        try:
            result = self.tech_fingerprint.fingerprint(target)
            waf = self.tech_fingerprint.detect_waf(target)
            result['waf'] = waf
            return result
        except Exception as e:
            logger.error(f"Fingerprinting error: {e}")
            return {'error': str(e)}
    
    def _run_crawler(self, target: str) -> Dict[str, Any]:
        """Run web crawler"""
        logger.info("Crawling website...")
        try:
            return self.crawler.crawl(target)
        except Exception as e:
            logger.error(f"Crawler error: {e}")
            return {'error': str(e)}
    
    def _run_header_scan(self, target: str) -> Dict[str, Any]:
        """Run security headers scan"""
        logger.info("Scanning security headers...")
        try:
            return self.header_scanner.scan(target)
        except Exception as e:
            logger.error(f"Header scan error: {e}")
            return {'error': str(e)}
    
    def _run_directory_scan(self, target: str) -> Dict[str, Any]:
        """Run directory enumeration"""
        logger.info("Enumerating directories...")
        try:
            return self.dir_finder.scan(target)
        except Exception as e:
            logger.error(f"Directory scan error: {e}")
            return {'error': str(e)}
    
    def _run_vulnerability_scans(self, target: str) -> List[Dict[str, Any]]:
        """Run all vulnerability scanners"""
        vulnerabilities = []
        
        # Get testable endpoints
        endpoints = self.crawler.get_testable_endpoints()
        
        if not endpoints:
            logger.warning("No testable endpoints found")
            return vulnerabilities
        
        logger.info(f"Testing {len(endpoints)} endpoints for vulnerabilities")
        
        # Test each endpoint
        for endpoint in endpoints[:10]:  # Limit to first 10 for demo
            url = endpoint['url']
            method = endpoint['method']
            params = endpoint['params']
            
            try:
                # SQL Injection
                logger.info(f"Testing SQL injection on {url}")
                vulns = self.sql_scanner.scan_url(url, params, method)
                vulnerabilities.extend(vulns)
                
                # XSS
                logger.info(f"Testing XSS on {url}")
                vulns = self.xss_scanner.scan_url(url, params, method)
                vulnerabilities.extend(vulns)
                
                # SSTI
                logger.info(f"Testing SSTI on {url}")
                vulns = self.ssti_scanner.scan_url(url, params, method)
                vulnerabilities.extend(vulns)
                
                # Command Injection
                logger.info(f"Testing command injection on {url}")
                vulns = self.cmd_scanner.scan_url(url, params, method)
                vulnerabilities.extend(vulns)
                
                # Path Traversal
                logger.info(f"Testing path traversal on {url}")
                vulns = self.path_scanner.scan_url(url, params, method)
                vulnerabilities.extend(vulns)
                
                # Open Redirect
                logger.info(f"Testing open redirect on {url}")
                vulns = self.redirect_scanner.scan_url(url, params, method)
                vulnerabilities.extend(vulns)
                
            except Exception as e:
                logger.error(f"Error testing {url}: {e}")
        
        return vulnerabilities
    
    def _run_network_scan(self, target: str) -> Dict[str, Any]:
        """Run network scans"""
        result = {}
        
        try:
            # Port scan
            logger.info("Scanning ports...")
            result['ports'] = self.port_scanner.scan_host(target)
            
            # SSL/TLS check (if HTTPS)
            if target.startswith('https'):
                logger.info("Checking SSL/TLS...")
                from urllib.parse import urlparse
                hostname = urlparse(target).netloc
                result['ssl'] = self.ssl_checker.check_ssl(hostname)
        
        except Exception as e:
            logger.error(f"Network scan error: {e}")
            result['error'] = str(e)
        
        return result
    
    def _run_ai_analysis(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run AI-powered analysis"""
        logger.info("Running AI analysis on findings...")
        
        try:
            # Analyze vulnerabilities with AI
            analyzed_vulns = self.ai_engine.batch_analyze(vulnerabilities)
            
            return {
                'analyzed_vulnerabilities': analyzed_vulns,
                'total_analyzed': len(analyzed_vulns),
                'ai_available': self.ai_engine.available
            }
        
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return {'error': str(e), 'ai_available': False}
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan summary"""
        
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            
            # Map vulnerability types to severity
            if 'sql' in vuln_type or 'command' in vuln_type or 'ssti' in vuln_type:
                severity_counts['critical'] += 1
            elif 'xss' in vuln_type or 'path traversal' in vuln_type:
                severity_counts['high'] += 1
            elif 'redirect' in vuln_type or 'header' in vuln_type:
                severity_counts['medium'] += 1
            else:
                severity_counts['low'] += 1
        
        # Overall risk level
        if severity_counts['critical'] > 0:
            risk_level = 'CRITICAL'
        elif severity_counts['high'] > 0:
            risk_level = 'HIGH'
        elif severity_counts['medium'] > 0:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low'],
            'risk_level': risk_level,
            'urls_crawled': results.get('crawler', {}).get('total_urls', 0),
            'forms_found': results.get('crawler', {}).get('total_forms', 0),
            'open_ports': results.get('network', {}).get('ports', {}).get('total_open', 0)
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    scanner = VulnerabilityScanner()
    
    results = scanner.full_scan("https://example.com")
    
    print(f"\n{'='*60}")
    print(f"Scan Summary:")
    print(f"{'='*60}")
    summary = results.get('summary', {})
    print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    print(f"  Critical: {summary.get('critical_count', 0)}")
    print(f"  High: {summary.get('high_count', 0)}")
    print(f"  Medium: {summary.get('medium_count', 0)}")
    print(f"  Low: {summary.get('low_count', 0)}")
    print(f"Overall Risk Level: {summary.get('risk_level', 'Unknown')}")
    print(f"{'='*60}")
