"""
AI-VulnScanner PRO Max - AI Engine Module
Handles communication with local AI models (Ollama/LM Studio)
Provides intelligent vulnerability analysis using FREE local models
"""

import requests
import json
import logging
from typing import Dict, List, Any, Optional
import time

class AIEngine:
    """
    AI Engine for vulnerability analysis using local models
    Supports: Ollama, LM Studio
    Models: LLaMA 3 8B, Mistral 7B, DeepSeek 7B, CodeLLaMA
    """
    
    def __init__(self, 
                 ollama_url: str = "http://localhost:11434/api/generate",
                 model: str = "llama3",
                 timeout: int = 30):
        """
        Initialize AI Engine
        
        Args:
            ollama_url: Ollama API endpoint
            model: AI model name (llama3, mistral, deepseek-coder, codellama)
            timeout: Request timeout in seconds
        """
        self.ollama_url = ollama_url
        self.model = model
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # Available models and their capabilities
        self.models = {
            "llama3": {"size": "4.7GB", "best_for": "General analysis"},
            "mistral": {"size": "4.1GB", "best_for": "Quick scans"},
            "deepseek-coder": {"size": "4.5GB", "best_for": "Code analysis"},
            "codellama": {"size": "3.8GB", "best_for": "Technical details"}
        }
        
    def check_availability(self) -> bool:
        """
        Check if Ollama service is available
        
        Returns:
            bool: True if service is running
        """
        try:
            response = requests.get(
                self.ollama_url.replace('/api/generate', '/api/tags'),
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            self.logger.warning(f"Ollama not available: {e}")
            return False
    
    def analyze_vulnerability(self, 
                            vulnerability_data: Dict[str, Any],
                            context: str = "") -> Dict[str, Any]:
        """
        Analyze vulnerability using AI
        
        Args:
            vulnerability_data: Raw vulnerability information
            context: Additional context about the scan
            
        Returns:
            Dict containing AI analysis with severity, CVE, remediation
        """
        try:
            # Build comprehensive prompt for AI
            prompt = self._build_analysis_prompt(vulnerability_data, context)
            
            # Query AI model
            response = self._query_ollama(prompt)
            
            # Parse and structure response
            analysis = self._parse_ai_response(response)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return self._fallback_analysis(vulnerability_data)
    
    def batch_analyze(self, 
                     vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze multiple vulnerabilities in batch
        
        Args:
            vulnerabilities: List of vulnerability data
            
        Returns:
            List of analyzed vulnerabilities with AI insights
        """
        results = []
        
        for vuln in vulnerabilities:
            analysis = self.analyze_vulnerability(vuln)
            results.append({
                **vuln,
                "ai_analysis": analysis
            })
            time.sleep(0.5)  # Rate limiting
            
        return results
    
    def summarize_scan(self, 
                      scan_results: Dict[str, Any]) -> str:
        """
        Generate AI-powered executive summary of scan
        
        Args:
            scan_results: Complete scan results
            
        Returns:
            String containing executive summary
        """
        try:
            prompt = f"""
            Analyze this security scan and provide an executive summary:
            
            Total Vulnerabilities: {len(scan_results.get('vulnerabilities', []))}
            Critical: {sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'Critical')}
            High: {sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'High')}
            Medium: {sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'Medium')}
            Low: {sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'Low')}
            
            Technologies: {', '.join(scan_results.get('technologies', []))}
            
            Provide:
            1. Overall risk assessment
            2. Top 3 priority fixes
            3. Security posture rating (1-10)
            4. Recommended next steps
            
            Format as professional executive summary.
            """
            
            response = self._query_ollama(prompt, max_tokens=500)
            return response
            
        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            return "AI summary unavailable. Please review detailed findings."
    
    def predict_cve(self, 
                   vulnerability_type: str,
                   technology: str,
                   version: str = "") -> List[str]:
        """
        Predict potential CVE IDs based on vulnerability type
        
        Args:
            vulnerability_type: Type of vulnerability (SQL injection, XSS, etc.)
            technology: Technology stack (Apache, PHP, etc.)
            version: Version number if known
            
        Returns:
            List of potential CVE IDs
        """
        try:
            prompt = f"""
            Based on this vulnerability information, suggest potential CVE IDs:
            
            Vulnerability: {vulnerability_type}
            Technology: {technology}
            Version: {version if version else "Unknown"}
            
            Return ONLY a JSON array of CVE IDs (e.g., ["CVE-2023-12345", "CVE-2024-67890"]).
            If unsure, return [].
            """
            
            response = self._query_ollama(prompt, max_tokens=200)
            
            # Try to parse JSON from response
            try:
                cves = json.loads(response)
                if isinstance(cves, list):
                    return cves
            except:
                pass
                
            return []
            
        except Exception as e:
            self.logger.error(f"CVE prediction failed: {e}")
            return []
    
    def calculate_exploitability(self, 
                                vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate exploitability score using AI
        
        Args:
            vulnerability_data: Vulnerability information
            
        Returns:
            Dict with exploitability metrics
        """
        try:
            prompt = f"""
            Rate the exploitability of this vulnerability:
            
            Type: {vulnerability_data.get('type', 'Unknown')}
            Location: {vulnerability_data.get('location', 'Unknown')}
            Details: {vulnerability_data.get('details', 'No details')}
            
            Provide JSON response with:
            {{
                "exploitability_score": 1-10,
                "attack_complexity": "Low|Medium|High",
                "privileges_required": "None|Low|High",
                "user_interaction": "None|Required",
                "scope": "Unchanged|Changed",
                "availability_impact": "None|Low|High",
                "confidentiality_impact": "None|Low|High",
                "integrity_impact": "None|Low|High"
            }}
            """
            
            response = self._query_ollama(prompt, max_tokens=300)
            
            try:
                return json.loads(response)
            except:
                return self._default_exploitability()
                
        except Exception as e:
            self.logger.error(f"Exploitability calculation failed: {e}")
            return self._default_exploitability()
    
    def _build_analysis_prompt(self, 
                              vulnerability_data: Dict[str, Any],
                              context: str) -> str:
        """
        Build comprehensive AI analysis prompt
        
        Args:
            vulnerability_data: Vulnerability information
            context: Additional context
            
        Returns:
            Formatted prompt string
        """
        prompt = f"""
        You are a cybersecurity expert analyzing a vulnerability scan. Analyze the following and return ONLY valid JSON.
        
        VULNERABILITY DATA:
        Type: {vulnerability_data.get('type', 'Unknown')}
        Location: {vulnerability_data.get('location', 'Unknown')}
        Details: {vulnerability_data.get('details', 'No details provided')}
        Evidence: {vulnerability_data.get('evidence', 'None')}
        
        CONTEXT:
        {context if context else 'General web application security scan'}
        
        REQUIRED JSON RESPONSE FORMAT:
        {{
            "vulnerability_name": "Descriptive name",
            "severity": "Critical|High|Medium|Low",
            "cvss_score": 0.0-10.0,
            "cve_references": ["CVE-YYYY-XXXXX"],
            "exploitability": "Easy|Medium|Hard",
            "impact_analysis": "Detailed impact description",
            "attack_scenario": "How attacker would exploit this",
            "remediation_steps": ["Step 1", "Step 2", "Step 3"],
            "security_recommendations": ["Recommendation 1", "Recommendation 2"],
            "false_positive_likelihood": "Low|Medium|High",
            "ai_confidence": 0-100
        }}
        
        Respond ONLY with valid JSON, no other text.
        """
        
        return prompt
    
    def _query_ollama(self, 
                     prompt: str,
                     max_tokens: int = 1000) -> str:
        """
        Query Ollama API
        
        Args:
            prompt: Prompt text
            max_tokens: Maximum response tokens
            
        Returns:
            AI response text
        """
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,  # Lower for more focused responses
                    "num_predict": max_tokens
                }
            }
            
            response = requests.post(
                self.ollama_url,
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', '').strip()
            else:
                raise Exception(f"API returned status {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Ollama query failed: {e}")
            raise
    
    def _parse_ai_response(self, response: str) -> Dict[str, Any]:
        """
        Parse AI response into structured format
        
        Args:
            response: Raw AI response
            
        Returns:
            Structured analysis dict
        """
        try:
            # Try to extract JSON from response
            start = response.find('{')
            end = response.rfind('}') + 1
            
            if start != -1 and end > start:
                json_str = response[start:end]
                return json.loads(json_str)
            else:
                # Fallback parsing
                return {
                    "vulnerability_name": "Detected Vulnerability",
                    "severity": "Medium",
                    "cvss_score": 5.0,
                    "raw_analysis": response
                }
                
        except Exception as e:
            self.logger.error(f"Response parsing failed: {e}")
            return {"error": "Failed to parse AI response", "raw": response}
    
    def _fallback_analysis(self, 
                          vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback analysis when AI is unavailable
        
        Args:
            vulnerability_data: Vulnerability information
            
        Returns:
            Basic analysis without AI
        """
        vuln_type = vulnerability_data.get('type', 'Unknown').lower()
        
        # Rule-based severity assessment
        severity_map = {
            'sql injection': ('Critical', 9.0),
            'command injection': ('Critical', 9.5),
            'ssti': ('Critical', 9.0),
            'xss': ('High', 7.0),
            'path traversal': ('High', 7.5),
            'open redirect': ('Medium', 5.0),
            'missing header': ('Low', 3.0)
        }
        
        severity, cvss = severity_map.get(vuln_type, ('Medium', 5.0))
        
        return {
            "vulnerability_name": vulnerability_data.get('type', 'Unknown Vulnerability'),
            "severity": severity,
            "cvss_score": cvss,
            "cve_references": [],
            "exploitability": "Medium",
            "impact_analysis": "Potential security risk detected",
            "remediation_steps": [
                "Review and validate finding",
                "Implement appropriate security controls",
                "Test fix thoroughly"
            ],
            "ai_confidence": 0,
            "note": "AI analysis unavailable - rule-based assessment"
        }
    
    def _default_exploitability(self) -> Dict[str, Any]:
        """
        Default exploitability metrics
        
        Returns:
            Default metrics dict
        """
        return {
            "exploitability_score": 5,
            "attack_complexity": "Medium",
            "privileges_required": "Low",
            "user_interaction": "None",
            "scope": "Unchanged",
            "availability_impact": "Low",
            "confidentiality_impact": "Low",
            "integrity_impact": "Low"
        }
