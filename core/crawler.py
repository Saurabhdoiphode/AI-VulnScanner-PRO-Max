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

logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Web crawler for discovering URLs, forms, and attack surfaces
    """
    
    def __init__(self, max_depth: int = 2, max_urls: int = 20, timeout: int = 5):
        """
        Initialize Web Crawler
        
        Args:
            max_depth: Maximum crawl depth (default: 2 for faster scans)
            max_urls: Maximum number of URLs to crawl (default: 20 for speed)
            timeout: Request timeout in seconds
        """
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.visited_urls: Set[str] = set()
        self.discovered_urls: List[Dict[str, Any]] = []
        self.forms: List[Dict[str, Any]] = []
    
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
        
        while queue and len(self.visited_urls) < self.max_urls:
            current_url, depth = queue.popleft()
            
            if depth > self.max_depth or current_url in self.visited_urls:
                continue
            
            try:
                logger.info(f"Crawling: {current_url} (depth: {depth})")
                self.visited_urls.add(current_url)
                
                response = self.session.get(current_url, timeout=self.timeout, verify=False)
                
                if response.status_code != 200:
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
                
                time.sleep(0.1)  # Rate limiting (reduced for faster scans)
            
            except Exception as e:
                logger.debug(f"Error crawling {current_url}: {e}")
        
        logger.info(f"Crawl complete. Found {len(self.visited_urls)} URLs and {len(self.forms)} forms")
        
        return {
            'urls': list(self.visited_urls),
            'discovered_urls': self.discovered_urls,
            'forms': self.forms,
            'total_urls': len(self.visited_urls),
            'total_forms': len(self.forms)
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
