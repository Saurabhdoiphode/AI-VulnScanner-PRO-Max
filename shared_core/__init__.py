"""
AI-VulnScanner PRO Max - Shared Core Modules
Used by both Desktop GUI and Web Application
"""

__version__ = "1.0.0"
__author__ = "AI-VulnScanner Team"

from shared_core.ai_engine import AIEngine
from shared_core.scanner import VulnerabilityScanner
from shared_core.report_generator import ReportGenerator

__all__ = [
    'AIEngine',
    'VulnerabilityScanner',
    'ReportGenerator'
]
