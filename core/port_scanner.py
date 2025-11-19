"""
Port Scanner Module
Network port scanning and service detection
"""

import socket
import threading
from typing import List, Dict, Any, Tuple
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class PortScanner:
    """
    Advanced port scanner with service detection
    """
    
    # Common ports and services
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    def __init__(self, timeout: float = 0.5, max_workers: int = 200):
        """
        Initialize Port Scanner
        
        Args:
            timeout: Socket connection timeout
            max_workers: Maximum concurrent threads
        """
        self.timeout = timeout
        self.max_workers = max_workers
    
    def scan_host(self, host: str, ports: List[int] = None, scan_all: bool = False) -> Dict[str, Any]:
        """
        Scan host for open ports
        
        Args:
            host: Target host IP or hostname
            ports: List of ports to scan (default: common ports)
            scan_all: Scan all 65535 ports
            
        Returns:
            Dict with scan results
        """
        logger.info(f"Starting port scan on {host}")
        
        if scan_all:
            ports_to_scan = range(1, 65536)
        elif ports:
            ports_to_scan = ports
        else:
            ports_to_scan = list(self.COMMON_PORTS.keys())
        
        open_ports = []
        closed_ports = []
        
        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self._scan_port, host, port): port 
                for port in ports_to_scan
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        service = self.COMMON_PORTS.get(port, 'Unknown')
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'banner': banner,
                            'state': 'open'
                        })
                        logger.info(f"  ✓ Port {port} ({service}) is open")
                    else:
                        closed_ports.append(port)
                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {e}")
        
        return {
            'host': host,
            'open_ports': sorted(open_ports, key=lambda x: x['port']),
            'total_open': len(open_ports),
            'total_scanned': len(ports_to_scan),
            'scan_type': 'full' if scan_all else 'common'
        }
    
    def _scan_port(self, host: str, port: int) -> Tuple[bool, str]:
        """
        Scan single port
        
        Args:
            host: Target host
            port: Port number
            
        Returns:
            Tuple of (is_open, banner)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Port is open, try to grab banner
                banner = self._grab_banner(sock, port)
                sock.close()
                return True, banner
            else:
                sock.close()
                return False, ""
        
        except socket.gaierror:
            logger.error(f"Hostname {host} could not be resolved")
            return False, ""
        except socket.error as e:
            logger.debug(f"Socket error on port {port}: {e}")
            return False, ""
    
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Attempt to grab service banner
        
        Args:
            sock: Connected socket
            port: Port number
            
        Returns:
            Banner string
        """
        try:
            # Some services send banner immediately
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if banner:
                return banner[:200]  # Limit banner length
            
            # For HTTP/HTTPS, send request
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:200]
            
            # For FTP, try to get welcome message
            if port == 21:
                return banner if banner else "FTP Service"
            
            # For SSH
            if port == 22:
                return banner if banner else "SSH Service"
            
            return ""
        
        except:
            return ""
    
    def detect_service_version(self, host: str, port: int) -> Dict[str, Any]:
        """
        Detailed service version detection
        
        Args:
            host: Target host
            port: Port number
            
        Returns:
            Dict with service details
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            
            banner = self._grab_banner(sock, port)
            sock.close()
            
            service_info = {
                'port': port,
                'banner': banner,
                'service': self._identify_service(banner, port),
                'version': self._extract_version(banner)
            }
            
            return service_info
        
        except Exception as e:
            logger.debug(f"Error detecting service on port {port}: {e}")
            return {}
    
    def _identify_service(self, banner: str, port: int) -> str:
        """Identify service from banner"""
        banner_lower = banner.lower()
        
        if 'apache' in banner_lower:
            return 'Apache HTTP Server'
        elif 'nginx' in banner_lower:
            return 'Nginx Web Server'
        elif 'microsoft-iis' in banner_lower:
            return 'Microsoft IIS'
        elif 'ssh' in banner_lower:
            return 'SSH Server'
        elif 'ftp' in banner_lower:
            return 'FTP Server'
        elif 'mysql' in banner_lower:
            return 'MySQL Database'
        elif 'postgresql' in banner_lower:
            return 'PostgreSQL Database'
        elif 'redis' in banner_lower:
            return 'Redis Server'
        elif 'mongodb' in banner_lower:
            return 'MongoDB Database'
        else:
            return self.COMMON_PORTS.get(port, 'Unknown Service')
    
    def _extract_version(self, banner: str) -> str:
        """Extract version from banner"""
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',
            r'v(\d+\.\d+)',
            r'version[\s:]+(\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return "Unknown"


# Example usage
if __name__ == "__main__":
    scanner = PortScanner()
    
    result = scanner.scan_host("127.0.0.1")
    
    print(f"\nPort Scan Results:")
    print(f"  Host: {result['host']}")
    print(f"  Open Ports: {result['total_open']}")
    
    for port_info in result['open_ports']:
        print(f"    Port {port_info['port']}: {port_info['service']}")
