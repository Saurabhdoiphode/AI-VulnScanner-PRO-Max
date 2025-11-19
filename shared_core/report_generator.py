"""
AI-VulnScanner PRO Max - Report Generator (Shared Core)
Generates professional HTML and PDF reports
Used by both Desktop GUI and Web Application
"""

import os
import json
import logging
from typing import Dict, List, Any
from datetime import datetime

class ReportGenerator:
    """
    Advanced report generator for vulnerability scans
    Supports: HTML, JSON, PDF (optional)
    """
    
    def __init__(self, output_dir: str = None):
        """
        Initialize report generator
        
        Args:
            output_dir: Directory to save reports
        """
        if output_dir is None:
            # Use shared reports directory
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            output_dir = os.path.join(base_dir, 'reports', 'output')
        
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate comprehensive HTML report
        
        Args:
            scan_results: Complete scan results dictionary
            
        Returns:
            Path to generated HTML file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{scan_results.get('scan_id', timestamp)}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        html_content = self._generate_html_content(scan_results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {filepath}")
        return filepath
    
    def generate_json_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate JSON report for programmatic access
        
        Args:
            scan_results: Complete scan results
            
        Returns:
            Path to JSON file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{scan_results.get('scan_id', timestamp)}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=2)
        
        self.logger.info(f"JSON report generated: {filepath}")
        return filepath
    
    def _generate_html_content(self, results: Dict[str, Any]) -> str:
        """Generate HTML report content"""
        
        # Extract data
        target = results.get('target', 'Unknown')
        scan_id = results.get('scan_id', 'N/A')
        start_time = results.get('start_time', 'N/A')
        duration = results.get('duration', 'N/A')
        stats = results.get('statistics', {})
        vulnerabilities = results.get('vulnerabilities', [])
        technologies = results.get('technologies', [])
        open_ports = results.get('open_ports', [])
        osint_data = results.get('osint_data', {})
        ai_summary = results.get('ai_summary', '')
        
        # Sort vulnerabilities by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        vulnerabilities.sort(key=lambda x: severity_order.get(x.get('severity', 'Low'), 4))
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.95;
        }}
        
        .header .scan-info {{
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }}
        
        .header .info-item {{
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            font-size: 1.8em;
        }}
        
        .statistics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            text-align: center;
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .stat-card .label {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .stat-card.critical {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        
        .stat-card.high {{
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }}
        
        .stat-card.medium {{
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
            color: #333;
        }}
        
        .stat-card.low {{
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
            color: #333;
        }}
        
        .ai-summary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}
        
        .ai-summary h3 {{
            margin-bottom: 15px;
            font-size: 1.5em;
        }}
        
        .ai-summary p {{
            line-height: 1.8;
            white-space: pre-wrap;
        }}
        
        .vulnerability {{
            background: white;
            border: 2px solid #e1e4e8;
            border-left: 5px solid #6c757d;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: box-shadow 0.3s;
        }}
        
        .vulnerability:hover {{
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }}
        
        .vulnerability.critical {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        
        .vulnerability.high {{
            border-left-color: #fd7e14;
            background: #fff9f5;
        }}
        
        .vulnerability.medium {{
            border-left-color: #ffc107;
            background: #fffef5;
        }}
        
        .vulnerability.low {{
            border-left-color: #28a745;
            background: #f5fff5;
        }}
        
        .vulnerability .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .vulnerability h3 {{
            color: #333;
            font-size: 1.3em;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .severity-badge.critical {{
            background: #dc3545;
        }}
        
        .severity-badge.high {{
            background: #fd7e14;
        }}
        
        .severity-badge.medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .severity-badge.low {{
            background: #28a745;
        }}
        
        .vulnerability .details {{
            margin: 15px 0;
            color: #555;
        }}
        
        .vulnerability .location {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
            word-break: break-all;
        }}
        
        .vulnerability .remediation {{
            background: #e7f3ff;
            border-left: 4px solid #0066cc;
            padding: 15px;
            margin-top: 15px;
            border-radius: 5px;
        }}
        
        .vulnerability .remediation h4 {{
            color: #0066cc;
            margin-bottom: 10px;
        }}
        
        .vulnerability .remediation ul {{
            margin-left: 20px;
        }}
        
        .vulnerability .remediation li {{
            margin: 5px 0;
        }}
        
        .technology-list, .port-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .tech-badge, .port-badge {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 10px 20px;
            border-radius: 20px;
            font-size: 0.9em;
        }}
        
        .osint-data {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
        }}
        
        .osint-data h4 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .osint-data pre {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #e1e4e8;
        }}
        
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-style: italic;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
            .vulnerability {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AI-VulnScanner PRO Max</h1>
            <div class="subtitle">Comprehensive Security Assessment Report</div>
            <div class="scan-info">
                <div class="info-item"><strong>Target:</strong> {target}</div>
                <div class="info-item"><strong>Scan ID:</strong> {scan_id}</div>
                <div class="info-item"><strong>Date:</strong> {start_time}</div>
                <div class="info-item"><strong>Duration:</strong> {duration}</div>
            </div>
        </div>
        
        <div class="content">
            <!-- Executive Summary Statistics -->
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="statistics">
                    <div class="stat-card">
                        <div class="number">{stats.get('total_vulnerabilities', 0)}</div>
                        <div class="label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card critical">
                        <div class="number">{stats.get('critical', 0)}</div>
                        <div class="label">Critical</div>
                    </div>
                    <div class="stat-card high">
                        <div class="number">{stats.get('high', 0)}</div>
                        <div class="label">High</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="number">{stats.get('medium', 0)}</div>
                        <div class="label">Medium</div>
                    </div>
                    <div class="stat-card low">
                        <div class="number">{stats.get('low', 0)}</div>
                        <div class="label">Low</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{stats.get('total_endpoints', 0)}</div>
                        <div class="label">Endpoints Tested</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{stats.get('open_ports', 0)}</div>
                        <div class="label">Open Ports</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{stats.get('technologies_detected', 0)}</div>
                        <div class="label">Technologies</div>
                    </div>
                </div>
            </div>
"""

        # AI Summary
        if ai_summary:
            html += f"""
            <div class="section">
                <div class="ai-summary">
                    <h3>🤖 AI-Powered Executive Summary</h3>
                    <p>{ai_summary}</p>
                </div>
            </div>
"""

        # Vulnerabilities
        html += f"""
            <div class="section">
                <h2>🔍 Detected Vulnerabilities ({len(vulnerabilities)})</h2>
"""
        
        if vulnerabilities:
            html += self._build_vulnerabilities_html(vulnerabilities)
        else:
            html += '<div class="no-data">✅ No vulnerabilities detected</div>'
        
        html += """
            </div>
"""

        # Technologies
        if technologies:
            html += f"""
            <div class="section">
                <h2>💻 Detected Technologies</h2>
                <div class="technology-list">
"""
            for tech in technologies:
                html += f'<span class="tech-badge">{tech}</span>'
            
            html += """
                </div>
            </div>
"""

        # Open Ports
        if open_ports:
            html += f"""
            <div class="section">
                <h2>🔓 Open Ports & Services</h2>
                <div class="port-list">
"""
            for port_info in open_ports:
                port = port_info.get('port', 'Unknown')
                service = port_info.get('service', 'Unknown')
                html += f'<span class="port-badge">{port} - {service}</span>'
            
            html += """
                </div>
            </div>
"""

        # OSINT Data
        if osint_data:
            html += """
            <div class="section">
                <h2>🕵️ OSINT Intelligence</h2>
"""
            html += self._build_osint_html(osint_data)
            html += """
            </div>
"""

        # Footer
        html += f"""
        </div>
        
        <div class="footer">
            <p><strong>AI-VulnScanner PRO Max</strong> - Enterprise Security Assessment Platform</p>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Report ID: {scan_id}</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _build_vulnerabilities_html(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Build HTML for vulnerabilities section"""
        html = ""
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low').lower()
            vuln_type = vuln.get('type', 'Unknown Vulnerability')
            location = vuln.get('location', 'N/A')
            details = vuln.get('details', 'No details available')
            evidence = vuln.get('evidence', '')
            remediation = vuln.get('remediation', [])
            ai_analysis = vuln.get('ai_analysis', {})
            
            html += f"""
                <div class="vulnerability {severity}">
                    <div class="vuln-header">
                        <h3>{vuln_type}</h3>
                        <span class="severity-badge {severity}">{severity.upper()}</span>
                    </div>
                    <div class="details">
                        <p>{details}</p>
                    </div>
                    <div class="location">
                        <strong>📍 Location:</strong> {location}
                    </div>
"""
            
            if evidence:
                html += f"""
                    <div class="location">
                        <strong>🔎 Evidence:</strong> {evidence}
                    </div>
"""
            
            # AI Analysis
            if ai_analysis and ai_analysis.get('impact_analysis'):
                html += f"""
                    <div class="location">
                        <strong>🤖 AI Impact Analysis:</strong> {ai_analysis.get('impact_analysis', '')}
                    </div>
"""
                
                if ai_analysis.get('cvss_score'):
                    html += f"""
                    <div class="location">
                        <strong>📊 CVSS Score:</strong> {ai_analysis.get('cvss_score', 'N/A')} | 
                        <strong>Exploitability:</strong> {ai_analysis.get('exploitability', 'Unknown')}
                    </div>
"""
            
            # Remediation
            if remediation or (ai_analysis and ai_analysis.get('remediation_steps')):
                steps = remediation or ai_analysis.get('remediation_steps', [])
                if steps:
                    html += """
                    <div class="remediation">
                        <h4>🛠️ Remediation Steps</h4>
                        <ul>
"""
                    for step in steps:
                        html += f"<li>{step}</li>"
                    
                    html += """
                        </ul>
                    </div>
"""
            
            html += """
                </div>
"""
        
        return html
    
    def _build_osint_html(self, osint_data: Dict[str, Any]) -> str:
        """Build HTML for OSINT section"""
        html = ""
        
        if osint_data.get('whois'):
            html += f"""
                <div class="osint-data">
                    <h4>WHOIS Information</h4>
                    <pre>{json.dumps(osint_data['whois'], indent=2)}</pre>
                </div>
"""
        
        if osint_data.get('dns_records'):
            html += f"""
                <div class="osint-data">
                    <h4>DNS Records</h4>
                    <pre>{json.dumps(osint_data['dns_records'], indent=2)}</pre>
                </div>
"""
        
        if osint_data.get('subdomains'):
            html += """
                <div class="osint-data">
                    <h4>Discovered Subdomains</h4>
                    <div class="technology-list">
"""
            for subdomain in osint_data['subdomains']:
                html += f'<span class="tech-badge">{subdomain}</span>'
            
            html += """
                    </div>
                </div>
"""
        
        if osint_data.get('geolocation'):
            html += f"""
                <div class="osint-data">
                    <h4>IP Geolocation</h4>
                    <pre>{json.dumps(osint_data['geolocation'], indent=2)}</pre>
                </div>
"""
        
        return html
