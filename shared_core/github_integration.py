"""
GitHub Integration Module
Pushes scan results to GitHub repository
"""

import os
import json
import base64
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger(__name__)


class GitHubIntegration:
    """
    Handles pushing scan results to GitHub repository
    """
    
    def __init__(self, repo_url: str, token: Optional[str] = None):
        """
        Initialize GitHub integration
        
        Args:
            repo_url: GitHub repository URL (e.g., https://github.com/user/repo.git)
            token: GitHub personal access token (optional, can use env var GITHUB_TOKEN)
        """
        self.repo_url = repo_url
        self.token = token or os.environ.get('GITHUB_TOKEN')
        
        # Parse repo info from URL
        self.owner, self.repo = self._parse_repo_url(repo_url)
        
        self.api_base = "https://api.github.com"
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AI-VulnScanner-PRO-Max'
        }
        
        if self.token:
            self.headers['Authorization'] = f'token {self.token}'
    
    def _parse_repo_url(self, url: str) -> tuple:
        """Parse owner and repo from GitHub URL"""
        # Handle various URL formats
        url = url.replace('https://github.com/', '').replace('git@github.com:', '').replace('.git', '')
        parts = url.split('/')
        if len(parts) >= 2:
            return parts[0], parts[1]
        raise ValueError(f"Invalid GitHub URL: {url}")
    
    def push_scan_results(self, results: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Push scan results to GitHub as a new file in the repository
        
        Args:
            results: Scan results dictionary
            target: Target that was scanned
            
        Returns:
            Dict with success status and details
        """
        try:
            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_target = target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
            filename = f"scan_results/{safe_target}_{timestamp}.json"
            
            # Prepare commit message
            commit_message = f"Add scan results for {target} - {timestamp}"
            
            # Create content
            content = json.dumps(results, indent=2, ensure_ascii=False)
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            
            # Check if file exists (it shouldn't for new scans)
            file_url = f"{self.api_base}/repos/{self.owner}/{self.repo}/contents/{filename}"
            
            # Create the file
            response = requests.put(
                file_url,
                headers=self.headers,
                json={
                    'message': commit_message,
                    'content': encoded_content,
                    'branch': 'main'
                },
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Successfully pushed scan results to GitHub: {filename}")
                return {
                    'success': True,
                    'filename': filename,
                    'commit_url': response.json().get('commit', {}).get('html_url'),
                    'file_url': response.json().get('content', {}).get('html_url')
                }
            else:
                logger.error(f"Failed to push to GitHub: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f"GitHub API error: {response.status_code} - {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error pushing to GitHub: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_summary_report(self, results: Dict[str, Any], target: str) -> str:
        """
        Create a markdown summary report from scan results
        
        Args:
            results: Scan results dictionary
            target: Target that was scanned
            
        Returns:
            Markdown formatted summary
        """
        stats = results.get('statistics', {})
        vulns = results.get('vulnerabilities', [])
        
        # Count by severity
        severity_counts = {
            'Critical': sum(1 for v in vulns if v.get('severity') == 'Critical'),
            'High': sum(1 for v in vulns if v.get('severity') == 'High'),
            'Medium': sum(1 for v in vulns if v.get('severity') == 'Medium'),
            'Low': sum(1 for v in vulns if v.get('severity') == 'Low')
        }
        
        md = f"""# AI-VulnScanner PRO Max - Scan Report

**Target:** {target}
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Scan ID:** {results.get('scan_id', 'N/A')}

## Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts['Critical']} |
| High | {severity_counts['High']} |
| Medium | {severity_counts['Medium']} |
| Low | {severity_counts['Low']} |
| **Total** | **{stats.get('total_vulnerabilities', 0)}** |

## Scan Coverage

- **URLs Tested:** {stats.get('total_endpoints', 0)}
- **Forms Analyzed:** {stats.get('total_forms', 0)}
- **Open Ports:** {stats.get('open_ports', 0)}
- **Technologies Detected:** {stats.get('technologies_detected', 0)}
- **Scan Duration:** {results.get('duration', 'N/A')}

## Detected Technologies

"""
        
        technologies = results.get('technologies', [])
        if technologies:
            for tech in technologies:
                md += f"- {tech}\n"
        else:
            md += "None detected\n"
        
        md += "\n## Open Ports\n\n"
        open_ports = results.get('open_ports', [])
        if open_ports:
            for port in open_ports:
                md += f"- Port {port.get('port', 'N/A')}: {port.get('service', 'Unknown')}\n"
        else:
            md += "None found\n"
        
        md += "\n## Vulnerabilities Found\n\n"
        if vulns:
            for i, vuln in enumerate(vulns, 1):
                md += f"### {i}. {vuln.get('type', 'Unknown')}\n"
                md += f"- **Severity:** {vuln.get('severity', 'Unknown')}\n"
                md += f"- **URL:** {vuln.get('url', vuln.get('endpoint', 'N/A'))}\n"
                if vuln.get('parameter'):
                    md += f"- **Parameter:** {vuln.get('parameter')}\n"
                if vuln.get('payload'):
                    md += f"- **Payload:** `{vuln.get('payload')}`\n"
                md += f"- **Description:** {vuln.get('description', vuln.get('details', 'N/A'))}\n\n"
        else:
            md += "No vulnerabilities found.\n"
        
        md += "---\n*Generated by AI-VulnScanner PRO Max*\n"
        
        return md
    
    def push_summary_report(self, results: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Push markdown summary report to GitHub
        
        Args:
            results: Scan results dictionary
            target: Target that was scanned
            
        Returns:
            Dict with success status and details
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_target = target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
            filename = f"scan_reports/{safe_target}_{timestamp}.md"
            
            commit_message = f"Add scan summary report for {target} - {timestamp}"
            
            content = self.create_summary_report(results, target)
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            
            file_url = f"{self.api_base}/repos/{self.owner}/{self.repo}/contents/{filename}"
            
            response = requests.put(
                file_url,
                headers=self.headers,
                json={
                    'message': commit_message,
                    'content': encoded_content,
                    'branch': 'main'
                },
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Successfully pushed summary report to GitHub: {filename}")
                return {
                    'success': True,
                    'filename': filename,
                    'commit_url': response.json().get('commit', {}).get('html_url'),
                    'file_url': response.json().get('content', {}).get('html_url')
                }
            else:
                logger.error(f"Failed to push summary to GitHub: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f"GitHub API error: {response.status_code} - {response.text}"
                }
                
        except Exception as e:
            logger.error(f"Error pushing summary to GitHub: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_connection(self) -> Dict[str, Any]:
        """
        Verify GitHub connection and repository access
        
        Returns:
            Dict with connection status
        """
        try:
            response = requests.get(
                f"{self.api_base}/repos/{self.owner}/{self.repo}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                repo_info = response.json()
                return {
                    'success': True,
                    'repo_name': repo_info.get('full_name'),
                    'private': repo_info.get('private'),
                    'default_branch': repo_info.get('default_branch', 'main')
                }
            else:
                return {
                    'success': False,
                    'error': f"Repository access failed: {response.status_code}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


def push_results_to_github(results: Dict[str, Any], target: str, repo_url: str, token: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to push scan results to GitHub
    
    Args:
        results: Scan results dictionary
        target: Target that was scanned
        repo_url: GitHub repository URL
        token: GitHub personal access token (optional)
        
    Returns:
        Dict with push results
    """
    github = GitHubIntegration(repo_url, token)
    
    # Verify connection first
    verify = github.verify_connection()
    if not verify['success']:
        return verify
    
    # Push JSON results
    json_result = github.push_scan_results(results, target)
    
    # Push markdown summary
    md_result = github.push_summary_report(results, target)
    
    return {
        'json_push': json_result,
        'markdown_push': md_result,
        'repo_info': verify
    }