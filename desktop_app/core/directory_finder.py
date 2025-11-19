"""
Directory and File Finder Module
Discovers hidden directories, admin panels, and sensitive files
"""

import requests
from typing import List, Dict, Any
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class DirectoryFinder:
    """
    Hidden directory and sensitive file scanner
    """
    
    # Common directory names
    COMMON_DIRS = [
        'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
        'backup', 'backups', 'old', 'temp', 'tmp', 'test', 'dev',
        'staging', 'api', 'uploads', 'images', 'files', 'download',
        'downloads', 'docs', 'documentation', 'dashboard', 'panel',
        'cpanel', 'config', 'conf', 'private', 'secret', 'hidden'
    ]
    
    # Sensitive files
    SENSITIVE_FILES = [
        '.env', '.git/config', '.svn/entries', 'config.php', 'config.yml',
        'database.yml', 'wp-config.php', 'web.config', 'backup.zip',
        'backup.sql', 'dump.sql', 'database.sql', '.htaccess', '.htpasswd',
        'phpinfo.php', 'info.php', 'test.php', 'robots.txt', 'sitemap.xml',
        'crossdomain.xml', 'clientaccesspolicy.xml', 'README.md', 'CHANGELOG',
        '.DS_Store', 'composer.json', 'package.json', 'yarn.lock',
        'Gemfile', 'Gemfile.lock', 'requirements.txt', 'settings.py',
        'docker-compose.yml', 'Dockerfile', '.dockerignore', '.gitignore'
    ]
    
    def __init__(self, timeout: int = 5, max_workers: int = 20):
        """
        Initialize Directory Finder
        
        Args:
            timeout: Request timeout
            max_workers: Maximum concurrent threads
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan(self, base_url: str, custom_wordlist: List[str] = None) -> Dict[str, Any]:
        """
        Scan for hidden directories and files
        
        Args:
            base_url: Base URL to scan
            custom_wordlist: Custom wordlist (optional)
            
        Returns:
            Dict with discovered paths
        """
        logger.info(f"Starting directory scan on {base_url}")
        
        if not base_url.endswith('/'):
            base_url += '/'
        
        found_dirs = []
        found_files = []
        
        # Scan directories
        dir_list = custom_wordlist if custom_wordlist else self.COMMON_DIRS
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_dir = {
                executor.submit(self._check_path, base_url + d): d 
                for d in dir_list
            }
            
            for future in as_completed(future_to_dir):
                dir_name = future_to_dir[future]
                try:
                    exists, status_code, size = future.result()
                    if exists:
                        found_dirs.append({
                            'path': dir_name,
                            'url': base_url + dir_name,
                            'status_code': status_code,
                            'size': size
                        })
                        logger.info(f"  ✓ Found directory: {dir_name}")
                except Exception as e:
                    logger.debug(f"Error checking {dir_name}: {e}")
        
        # Scan sensitive files
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self._check_path, base_url + f): f 
                for f in self.SENSITIVE_FILES
            }
            
            for future in as_completed(future_to_file):
                file_name = future_to_file[future]
                try:
                    exists, status_code, size = future.result()
                    if exists:
                        found_files.append({
                            'path': file_name,
                            'url': base_url + file_name,
                            'status_code': status_code,
                            'size': size,
                            'risk': self._assess_file_risk(file_name)
                        })
                        logger.warning(f"  ✗ Found sensitive file: {file_name}")
                except Exception as e:
                    logger.debug(f"Error checking {file_name}: {e}")
        
        return {
            'base_url': base_url,
            'directories': found_dirs,
            'sensitive_files': found_files,
            'total_directories': len(found_dirs),
            'total_files': len(found_files)
        }
    
    def _check_path(self, url: str) -> tuple:
        """
        Check if path exists
        
        Returns:
            Tuple of (exists, status_code, size)
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            # Consider 200, 401, 403 as "found"
            if response.status_code in [200, 401, 403]:
                size = len(response.content)
                return True, response.status_code, size
            
            return False, response.status_code, 0
        
        except requests.exceptions.Timeout:
            return False, 0, 0
        except Exception as e:
            logger.debug(f"Error checking {url}: {e}")
            return False, 0, 0
    
    def _assess_file_risk(self, filename: str) -> str:
        """Assess security risk of exposed file"""
        critical_files = ['.env', 'config.php', 'wp-config.php', 'database.yml', 
                         'backup.zip', 'backup.sql', 'dump.sql', '.htpasswd']
        
        high_risk_files = ['.git/config', 'web.config', 'phpinfo.php', 
                          'composer.json', 'docker-compose.yml']
        
        if filename in critical_files:
            return 'Critical'
        elif filename in high_risk_files:
            return 'High'
        else:
            return 'Medium'


# Example usage
if __name__ == "__main__":
    finder = DirectoryFinder()
    
    result = finder.scan("https://example.com")
    
    print(f"\nDirectory Scan Results:")
    print(f"  Directories found: {result['total_directories']}")
    print(f"  Sensitive files found: {result['total_files']}")
