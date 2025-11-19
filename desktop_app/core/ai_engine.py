"""
AI Engine Module - Local AI Integration
Supports Ollama and LM Studio for free local AI inference
Analyzes vulnerabilities and provides intelligent insights
"""

import requests
import json
import logging
from typing import Dict, List, Any, Optional
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AIEngine:
    """
    AI Engine for vulnerability analysis using local models
    Supports Ollama (primary) and LM Studio (fallback)
    """
    
    def __init__(self, model_name: str = "llama3", ollama_url: str = "http://localhost:11434"):
        """
        Initialize AI Engine
        
        Args:
            model_name: Name of the model to use (llama3, mistral, deepseek-coder, codellama)
            ollama_url: Base URL for Ollama API
        """
        self.model_name = model_name
        self.ollama_url = ollama_url
        self.api_endpoint = f"{ollama_url}/api/generate"
        self.available = self.check_availability()
        
    def check_availability(self) -> bool:
        """
        Check if Ollama service is available
        
        Returns:
            bool: True if service is available
        """
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                logger.info("✓ Ollama service is available")
                return True
        except Exception as e:
            logger.warning(f"⚠ Ollama service not available: {e}")
            return False
    
    def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze vulnerability data using AI
        
        Args:
            vuln_data: Dictionary containing vulnerability information
            
        Returns:
            Dict with AI analysis results
        """
        if not self.available:
            return self._fallback_analysis(vuln_data)
        
        prompt = self._build_analysis_prompt(vuln_data)
        
        try:
            response = self._query_ollama(prompt)
            return self._parse_ai_response(response, vuln_data)
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return self._fallback_analysis(vuln_data)
    
    def _build_analysis_prompt(self, vuln_data: Dict[str, Any]) -> str:
        """
        Build detailed analysis prompt for AI
        
        Args:
            vuln_data: Vulnerability data dictionary
            
        Returns:
            str: Formatted prompt
        """
        prompt = f"""You are a cybersecurity expert analyzing web application vulnerabilities. 
Analyze the following security finding and provide a comprehensive assessment.

VULNERABILITY DATA:
Type: {vuln_data.get('type', 'Unknown')}
URL: {vuln_data.get('url', 'N/A')}
Method: {vuln_data.get('method', 'GET')}
Payload: {vuln_data.get('payload', 'N/A')}
Response: {vuln_data.get('response_snippet', 'N/A')[:500]}
Status Code: {vuln_data.get('status_code', 'N/A')}

ANALYSIS REQUIRED:
1. Vulnerability Classification (SQL Injection, XSS, SSTI, etc.)
2. Severity Level (Critical/High/Medium/Low)
3. CVSS v3.1 Score Prediction (0-10)
4. Potential CVE References (if applicable)
5. Exploitability Assessment (Easy/Medium/Hard)
6. Business Impact Analysis
7. Detailed Remediation Steps
8. Additional Security Recommendations

Respond in valid JSON format with these exact keys:
{{
    "vulnerability_name": "string",
    "severity": "Critical|High|Medium|Low",
    "cvss_score": "float 0-10",
    "cve_references": ["CVE-XXXX-XXXX"],
    "exploitability": "Easy|Medium|Hard",
    "impact_analysis": "string",
    "remediation_steps": ["step1", "step2"],
    "security_recommendations": ["rec1", "rec2"],
    "ai_confidence": "float 0-1"
}}

Provide your analysis:"""
        
        return prompt
    
    def _query_ollama(self, prompt: str, max_retries: int = 3) -> str:
        """
        Query Ollama API with retry logic
        
        Args:
            prompt: The prompt to send
            max_retries: Maximum number of retry attempts
            
        Returns:
            str: AI response text
        """
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "temperature": 0.3,  # Lower temperature for more consistent technical analysis
            "max_tokens": 1000
        }
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Querying AI model: {self.model_name} (attempt {attempt + 1})")
                response = requests.post(
                    self.api_endpoint,
                    json=payload,
                    timeout=60
                )
                
                if response.status_code == 200:
                    result = response.json()
                    return result.get('response', '')
                else:
                    logger.warning(f"API returned status {response.status_code}")
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout (attempt {attempt + 1})")
                time.sleep(2)
            except Exception as e:
                logger.error(f"Query error: {e}")
                time.sleep(2)
        
        raise Exception("Failed to get AI response after retries")
    
    def _parse_ai_response(self, response: str, original_data: Dict) -> Dict[str, Any]:
        """
        Parse AI response and extract structured data
        
        Args:
            response: Raw AI response
            original_data: Original vulnerability data
            
        Returns:
            Dict with parsed analysis
        """
        try:
            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                parsed = json.loads(json_str)
                
                # Ensure all required fields are present
                return {
                    'vulnerability_name': parsed.get('vulnerability_name', original_data.get('type', 'Unknown')),
                    'severity': parsed.get('severity', 'Medium'),
                    'cvss_score': float(parsed.get('cvss_score', 5.0)),
                    'cve_references': parsed.get('cve_references', []),
                    'exploitability': parsed.get('exploitability', 'Medium'),
                    'impact_analysis': parsed.get('impact_analysis', 'Impact analysis not available'),
                    'remediation_steps': parsed.get('remediation_steps', ['Consult security documentation']),
                    'security_recommendations': parsed.get('security_recommendations', []),
                    'ai_confidence': float(parsed.get('ai_confidence', 0.7)),
                    'raw_ai_response': response[:500]
                }
            else:
                raise ValueError("No JSON found in response")
                
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            return self._fallback_analysis(original_data)
    
    def _fallback_analysis(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Provide rule-based fallback analysis when AI is unavailable
        
        Args:
            vuln_data: Vulnerability data
            
        Returns:
            Dict with fallback analysis
        """
        vuln_type = vuln_data.get('type', 'Unknown').lower()
        
        # Rule-based severity mapping
        severity_map = {
            'sql injection': ('Critical', 9.5, ['CWE-89']),
            'command injection': ('Critical', 9.8, ['CWE-78']),
            'ssti': ('Critical', 9.0, ['CWE-94']),
            'xss': ('High', 7.5, ['CWE-79']),
            'path traversal': ('High', 7.0, ['CWE-22']),
            'open redirect': ('Medium', 5.0, ['CWE-601']),
            'missing header': ('Low', 3.0, ['CWE-693']),
        }
        
        # Find matching severity
        severity, cvss, cwe = ('Medium', 5.0, ['CWE-Other'])
        for key, value in severity_map.items():
            if key in vuln_type:
                severity, cvss, cwe = value
                break
        
        return {
            'vulnerability_name': vuln_data.get('type', 'Unknown Vulnerability'),
            'severity': severity,
            'cvss_score': cvss,
            'cve_references': cwe,
            'exploitability': 'Medium',
            'impact_analysis': f'Potential {severity.lower()} impact vulnerability detected.',
            'remediation_steps': [
                'Implement input validation',
                'Use parameterized queries',
                'Apply security headers',
                'Update to latest security patches'
            ],
            'security_recommendations': [
                'Conduct regular security audits',
                'Implement WAF protection',
                'Enable security logging'
            ],
            'ai_confidence': 0.6,
            'raw_ai_response': 'Fallback rule-based analysis (AI unavailable)'
        }
    
    def batch_analyze(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze multiple vulnerabilities in batch
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of analysis results
        """
        results = []
        total = len(vulnerabilities)
        
        logger.info(f"Starting batch analysis of {total} vulnerabilities")
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            logger.info(f"Analyzing vulnerability {idx}/{total}")
            analysis = self.analyze_vulnerability(vuln)
            results.append({**vuln, 'ai_analysis': analysis})
            time.sleep(0.5)  # Rate limiting
        
        return results
    
    def summarize_scan(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate AI-powered scan summary
        
        Args:
            scan_results: Complete scan results
            
        Returns:
            str: Natural language summary
        """
        if not self.available:
            return self._generate_basic_summary(scan_results)
        
        prompt = f"""Provide a concise executive summary of this security scan:

Total Vulnerabilities Found: {scan_results.get('total_vulnerabilities', 0)}
Critical: {scan_results.get('critical_count', 0)}
High: {scan_results.get('high_count', 0)}
Medium: {scan_results.get('medium_count', 0)}
Low: {scan_results.get('low_count', 0)}

Target: {scan_results.get('target', 'Unknown')}

Generate a 3-4 sentence executive summary highlighting the most critical findings and overall risk level."""
        
        try:
            summary = self._query_ollama(prompt)
            return summary.strip()
        except:
            return self._generate_basic_summary(scan_results)
    
    def _generate_basic_summary(self, scan_results: Dict[str, Any]) -> str:
        """Generate basic summary without AI"""
        total = scan_results.get('total_vulnerabilities', 0)
        critical = scan_results.get('critical_count', 0)
        high = scan_results.get('high_count', 0)
        
        if critical > 0:
            risk = "CRITICAL"
        elif high > 0:
            risk = "HIGH"
        else:
            risk = "MODERATE"
        
        return f"""Security scan completed for {scan_results.get('target', 'target')}. 
Found {total} total vulnerabilities with {critical} critical and {high} high severity issues. 
Overall risk level: {risk}. Immediate remediation recommended for critical findings."""


# Example usage and testing
if __name__ == "__main__":
    # Test AI engine
    ai = AIEngine(model_name="llama3")
    
    test_vuln = {
        'type': 'SQL Injection',
        'url': 'https://example.com/login',
        'method': 'POST',
        'payload': "' OR 1=1--",
        'response_snippet': 'MySQL error: You have an error in your SQL syntax',
        'status_code': 500
    }
    
    print("Testing AI vulnerability analysis...")
    result = ai.analyze_vulnerability(test_vuln)
    print(json.dumps(result, indent=2))
