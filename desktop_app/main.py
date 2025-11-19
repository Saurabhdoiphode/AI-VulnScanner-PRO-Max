"""
AI-VulnScanner PRO Max - Main Entry Point
Enterprise-level AI-powered cybersecurity vulnerability scanner
Author: GitHub Copilot
Version: 1.0.0
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from gui.login import LoginWindow

def main():
    """
    Main entry point for AI-VulnScanner PRO Max
    """
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║          AI-VulnScanner PRO Max v1.0.0                       ║
    ║          Enterprise Cybersecurity Scanner                    ║
    ║          Powered by Free Local AI Models                     ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Create necessary directories
    create_directories()
    
    # Initialize and start the login window
    app = LoginWindow()
    app.run()

def create_directories():
    """
    Create all necessary directories for the application
    """
    directories = [
        'reports/output',
        'reports/templates',
        'database',
        'logs',
        'core',
        'gui'
    ]
    
    for directory in directories:
        path = project_root / directory
        path.mkdir(parents=True, exist_ok=True)
        print(f"[✓] Directory ensured: {directory}")

if __name__ == "__main__":
    main()
