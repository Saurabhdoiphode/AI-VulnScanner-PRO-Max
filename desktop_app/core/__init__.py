# Core scanning modules package
"""
AI-VulnScanner PRO Max - Core Scanning Modules
"""

__version__ = "1.0.0"
__author__ = "GitHub Copilot"

# Import main components for easy access
from core.scanner import VulnerabilityScanner
from core.ai_engine import AIEngine

__all__ = [
    'VulnerabilityScanner',
    'AIEngine'
]
