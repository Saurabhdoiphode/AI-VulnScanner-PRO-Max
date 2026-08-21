"""
Web Crawler Module
Discovers URLs, forms, and endpoints for scanning
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Set, Any
import logging
import time
from collections import deque
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Web crawler for discovering URLs, forms, and attack surfaces
    """
    
    def __init__(self, max_depth: int = 3, max_urls: int = 200, timeout: int = 10, max_retries: int = 3):
        """
        Initialize Web Crawler
        
        Args:
            max_depth: Maximum crawl depth (default: 3 for thorough scans)
            max_urls: Maximum number of URLs to crawl (default: 200 for large sites)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
        """
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Create session with retry strategy
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.visited_urls: Set[str] = set()
        self.discovered_urls: List[Dict[str, Any]] = []
        self.forms: List[Dict[str, Any]] = []
        self.failed_urls: List[Dict[str, Any]] = []
        self.connection_errors = 0
        self.max_connection_errors = 50  # Stop if too many connection errors
    
    def crawl(self, start_url: str) -> Dict[str, Any]:
        """
        Crawl website starting from given URL
        
        Args:
            start_url: Starting URL
            
        Returns:
            Dict containing discovered URLs and forms
        """
        logger.info(f"Starting crawl from: {start_url}")
        
        base_domain = urlparse(start_url).netloc
        queue = deque([(start_url, 0)])  # (url, depth)
        
        consecutive_errors = 0
        max_consecutive_errors = 10
        
        while queue and len(self.visited_urls) < self.max_urls:
            current_url, depth = queue.popleft()
            
            if depth > self.max_depth or current_url in self.visited_urls:
                continue
            
            try:
                logger.info(f"Crawling: {current_url} (depth: {depth})")
                self.visited_urls.add(current_url)
                consecutive_errors = 0  # Reset on success
                
                response = self.session.get(
                    current_url, 
                    timeout=self.timeout, 
                    verify=False,
                    allow_redirects=True
                )
                
                if response.status_code != 200:
                    logger.debug(f"Non-200 status for {current_url}: {response.status_code}")
                    continue
                
                # Parse HTML
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                self._extract_forms(soup, current_url)
                
                # Extract links
                new_links = self._extract_links(soup, current_url, base_domain)
                
                # Add new links to queue
                for link in new_links:
                    if link not in self.visited_urls:
                        queue.append((link, depth + 1))
                        self.discovered_urls.append({
                            'url': link,
                            'depth': depth + 1,
                            'source': current_url
                        })
            
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout crawling {current_url}")
                self.connection_errors += 1
                consecutive_errors += 1
                self.failed_urls.append({
                    'url': current_url,
                    'error': 'Timeout',
                    'depth': depth
                })
                
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error for {current_url}")
                self.connection_errors += 1
                consecutive_errors += 1
                self.failed_urls.append({
                    'url': current_url,
                    'error': 'Connection Error',
                    'depth': depth
                })
                
            except requests.exceptions.TooManyRedirects:
                logger.warning(f"Too many redirects for {current_url}")
                self.connection_errors += 1
                consecutive_errors += 1
                self.failed_urls.append({
                    'url': current_url,
                    'error': 'Too Many Redirects',
                    'depth': depth
                })
                
            except Exception as e:
                logger.debug(f"Error crawling {current_url}: {e}")
                self.connection_errors += 1
                consecutive_errors += 1
                self.failed_urls.append({
                    'url': current_url,
                    'error': str(e)[:100],
                    'depth': depth
                })
            
            # Stop if too many consecutive errors (likely network issue)
            if consecutive_errors >= max_consecutive_errors:
                logger.warning(f"Too many consecutive errors ({consecutive_errors}), pausing crawl")
                time.sleep(5)  # Wait before continuing
                consecutive_errors = 0
            
            # Stop if too many total connection errors
            if self.connection_errors >= self.max_connection_errors:
                logger.warning(f"Max connection errors reached ({self.max_connection_errors}), stopping crawl")
                break
        
        logger.info(f"Crawl complete. Found {len(self.visited_urls)} URLs, {len(self.forms)} forms, {len(self.failed_urls)} failed")
        
        return {
            'urls': list(self.visited_urls),
            'discovered_urls': self.discovered_urls,
            'forms': self.forms,
            'failed_urls': self.failed_urls,
            'total_urls': len(self.visited_urls),
            'total_forms': len(self.forms),
            'connection_errors': self.connection_errors
        }
    
    def _extract_links(self, soup: BeautifulSoup, current_url: str, base_domain: str) -> List[str]:
        """Extract all links from page"""
        links = []
        
        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if not href:
                continue
            
            # Convert relative URLs to absolute
            absolute_url = urljoin(current_url, href)
            
            # Only include same-domain URLs
            if urlparse(absolute_url).netloc == base_domain:
                # Remove fragments
                absolute_url = absolute_url.split('#')[0]
                
                if absolute_url and absolute_url not in self.visited_urls:
                    links.append(absolute_url)
        
        return links
    
    def _extract_forms(self, soup: BeautifulSoup, current_url: str):
        """Extract all forms from page"""
        for form in soup.find_all('form'):
            form_details = {
                'url': current_url,
                'action': urljoin(current_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Extract form inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                
                if input_name:
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
            
            if form_details['inputs']:  # Only add forms with inputs
                self.forms.append(form_details)
    
    def get_testable_endpoints(self) -> List[Dict[str, Any]]:
        """
        Get list of endpoints suitable for vulnerability testing
        
        Returns:
            List of testable endpoints with parameters
        """
        endpoints = []
        
        # URLs with query parameters
        for url_info in self.discovered_urls:
            url = url_info['url']
            parsed = urlparse(url)
            
            if parsed.query:
                params = parse_qs(parsed.query)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                # Convert params to simple dict
                simple_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                
                endpoints.append({
                    'url': base_url,
                    'method': 'GET',
                    'params': simple_params,
                    'type': 'url_params'
                })
        
        # Forms
        for form in self.forms:
            if form['inputs']:
                params = {inp['name']: inp['value'] for inp in form['inputs'] if inp['name']}
                
                endpoints.append({
                    'url': form['action'],
                    'method': form['method'],
                    'params': params,
                    'type': 'form'
                })
        
        return endpoints


# Example usage
if __name__ == "__main__":
    crawler = WebCrawler(max_depth=2, max_urls=50)
    
    result = crawler.crawl("https://example.com")
    
    print(f"\nCrawl Results:")
    print(f"  Total URLs: {result['total_urls']}")
    print(f"  Total Forms: {result['total_forms']}")
    
    endpoints = crawler.get_testable_endpoints()
    print(f"  Testable Endpoints: {len(endpoints)}")
