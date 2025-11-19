"""
Main Dashboard - Primary Application Interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import logging
from datetime import datetime
from pathlib import Path
import json

from core.scanner import VulnerabilityScanner


class Dashboard:
    """
    Main application dashboard with tabbed interface
    """
    
    def __init__(self, username: str):
        self.username = username
        self.root = tk.Tk()
        self.root.title(f"AI-VulnScanner PRO Max - Dashboard [{username}]")
        self.root.geometry("1400x900")
        
        # Dark theme colors
        self.bg_color = "#1e1e1e"
        self.fg_color = "#ffffff"
        self.accent_color = "#007acc"
        self.button_color = "#0e639c"
        self.text_bg = "#2d2d2d"
        
        self.root.configure(bg=self.bg_color)
        
        # Scanner instance
        self.scanner = None
        self.scan_running = False
        self.scan_results = None
        
        # Configure logging
        self.setup_logging()
        
        # Create UI
        self.create_menu()
        self.create_widgets()
        
        # Center window
        self.center_window()
    
    def setup_logging(self):
        """Setup logging to file and GUI"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root, bg=self.text_bg, fg=self.fg_color)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=self.text_bg, fg=self.fg_color)
        file_menu.add_command(label="New Scan", command=self.new_scan)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg=self.text_bg, fg=self.fg_color)
        tools_menu.add_command(label="Settings", command=self.show_settings)
        tools_menu.add_command(label="View Logs", command=self.view_logs)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=self.text_bg, fg=self.fg_color)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_widgets(self):
        """Create main dashboard widgets"""
        
        # Top frame - Header
        header_frame = tk.Frame(self.root, bg=self.accent_color, height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="AI-VulnScanner PRO Max",
            font=("Arial", 20, "bold"),
            fg=self.fg_color,
            bg=self.accent_color
        )
        title_label.pack(side=tk.LEFT, padx=20, pady=15)
        
        user_label = tk.Label(
            header_frame,
            text=f"User: {self.username}",
            font=("Arial", 11),
            fg=self.fg_color,
            bg=self.accent_color
        )
        user_label.pack(side=tk.RIGHT, padx=20)
        
        # Main content frame
        content_frame = tk.Frame(self.root, bg=self.bg_color)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook (tabbed interface)
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', background=self.text_bg, foreground=self.fg_color,
                       padding=[20, 10], font=('Arial', 10))
        style.map('TNotebook.Tab', background=[('selected', self.accent_color)])
        
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_web_scanner_tab()
        self.create_network_scanner_tab()
        self.create_osint_tab()
        self.create_ai_analysis_tab()
        self.create_reports_tab()
        
        # Bottom frame - Status bar
        status_frame = tk.Frame(self.root, bg=self.text_bg, height=30)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            font=("Arial", 9),
            fg=self.fg_color,
            bg=self.text_bg,
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, padx=10)
    
    def create_web_scanner_tab(self):
        """Create web vulnerability scanner tab"""
        tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(tab, text="🌐 Web Scanner")
        
        # Target input frame
        input_frame = tk.Frame(tab, bg=self.bg_color)
        input_frame.pack(fill=tk.X, padx=20, pady=20)
        
        tk.Label(
            input_frame,
            text="Target URL:",
            font=("Arial", 11),
            fg=self.fg_color,
            bg=self.bg_color
        ).grid(row=0, column=0, sticky="w", pady=5)
        
        self.web_target_entry = tk.Entry(
            input_frame,
            font=("Arial", 11),
            width=60,
            bg=self.text_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.web_target_entry.grid(row=0, column=1, padx=10, pady=5)
        self.web_target_entry.insert(0, "https://example.com")
        
        # Scan options
        options_frame = tk.LabelFrame(
            tab,
            text="Scan Options",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        options_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.web_options = {}
        options = [
            ("SQL Injection", "sql_injection"),
            ("Cross-Site Scripting (XSS)", "xss"),
            ("SSTI", "ssti"),
            ("Command Injection", "cmd_injection"),
            ("Path Traversal", "path_traversal"),
            ("Open Redirect", "open_redirect"),
            ("Directory Enumeration", "dir_enum"),
            ("Security Headers", "headers")
        ]
        
        for i, (label, key) in enumerate(options):
            var = tk.BooleanVar(value=True)
            self.web_options[key] = var
            cb = tk.Checkbutton(
                options_frame,
                text=label,
                variable=var,
                font=("Arial", 9),
                fg=self.fg_color,
                bg=self.bg_color,
                selectcolor=self.text_bg
            )
            cb.grid(row=i // 4, column=i % 4, sticky="w", padx=10, pady=5)
        
        # Action buttons
        button_frame = tk.Frame(tab, bg=self.bg_color)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.web_scan_button = tk.Button(
            button_frame,
            text="▶ Start Web Scan",
            font=("Arial", 11, "bold"),
            bg=self.button_color,
            fg=self.fg_color,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.start_web_scan,
            width=20
        )
        self.web_scan_button.pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            button_frame,
            text="⏹ Stop Scan",
            font=("Arial", 11),
            bg="#c42b1c",
            fg=self.fg_color,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.stop_scan,
            width=15
        ).pack(side=tk.LEFT, padx=5)
        
        # Progress
        self.web_progress = ttk.Progressbar(
            tab,
            mode='indeterminate',
            length=300
        )
        self.web_progress.pack(pady=10)
        
        # Results area
        results_frame = tk.LabelFrame(
            tab,
            text="Scan Results",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.web_results_text = scrolledtext.ScrolledText(
            results_frame,
            font=("Consolas", 9),
            bg=self.text_bg,
            fg="#00ff00",
            insertbackground=self.fg_color,
            wrap=tk.WORD,
            height=20
        )
        self.web_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_network_scanner_tab(self):
        """Create network scanner tab"""
        tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(tab, text="🔌 Network Scanner")
        
        # Target input
        input_frame = tk.Frame(tab, bg=self.bg_color)
        input_frame.pack(fill=tk.X, padx=20, pady=20)
        
        tk.Label(
            input_frame,
            text="Target Host/IP:",
            font=("Arial", 11),
            fg=self.fg_color,
            bg=self.bg_color
        ).grid(row=0, column=0, sticky="w")
        
        self.network_target_entry = tk.Entry(
            input_frame,
            font=("Arial", 11),
            width=40,
            bg=self.text_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.network_target_entry.grid(row=0, column=1, padx=10)
        self.network_target_entry.insert(0, "127.0.0.1")
        
        # Scan options
        options_frame = tk.LabelFrame(
            tab,
            text="Scan Type",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        options_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.network_scan_type = tk.StringVar(value="common")
        
        tk.Radiobutton(
            options_frame,
            text="Common Ports (Fast)",
            variable=self.network_scan_type,
            value="common",
            font=("Arial", 9),
            fg=self.fg_color,
            bg=self.bg_color,
            selectcolor=self.text_bg
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        tk.Radiobutton(
            options_frame,
            text="Full Port Scan (1-65535)",
            variable=self.network_scan_type,
            value="full",
            font=("Arial", 9),
            fg=self.fg_color,
            bg=self.bg_color,
            selectcolor=self.text_bg
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        self.ssl_check_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            options_frame,
            text="SSL/TLS Security Check",
            variable=self.ssl_check_var,
            font=("Arial", 9),
            fg=self.fg_color,
            bg=self.bg_color,
            selectcolor=self.text_bg
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        # Buttons
        button_frame = tk.Frame(tab, bg=self.bg_color)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Button(
            button_frame,
            text="▶ Start Network Scan",
            font=("Arial", 11, "bold"),
            bg=self.button_color,
            fg=self.fg_color,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.start_network_scan,
            width=20
        ).pack(side=tk.LEFT, padx=5)
        
        # Results
        results_frame = tk.LabelFrame(
            tab,
            text="Network Scan Results",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.network_results_text = scrolledtext.ScrolledText(
            results_frame,
            font=("Consolas", 9),
            bg=self.text_bg,
            fg="#00ff00",
            insertbackground=self.fg_color,
            wrap=tk.WORD
        )
        self.network_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_osint_tab(self):
        """Create OSINT tab"""
        tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(tab, text="🔍 OSINT")
        
        # Target input
        input_frame = tk.Frame(tab, bg=self.bg_color)
        input_frame.pack(fill=tk.X, padx=20, pady=20)
        
        tk.Label(
            input_frame,
            text="Target Domain:",
            font=("Arial", 11),
            fg=self.fg_color,
            bg=self.bg_color
        ).grid(row=0, column=0, sticky="w")
        
        self.osint_target_entry = tk.Entry(
            input_frame,
            font=("Arial", 11),
            width=40,
            bg=self.text_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.osint_target_entry.grid(row=0, column=1, padx=10)
        self.osint_target_entry.insert(0, "example.com")
        
        # OSINT modules
        modules_frame = tk.LabelFrame(
            tab,
            text="OSINT Modules",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        modules_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.osint_modules = {}
        modules = [
            "WHOIS Lookup", "DNS Records", "Subdomain Discovery",
            "IP Geolocation", "Technology Fingerprinting", "WAF Detection"
        ]
        
        for i, module in enumerate(modules):
            var = tk.BooleanVar(value=True)
            self.osint_modules[module] = var
            tk.Checkbutton(
                modules_frame,
                text=module,
                variable=var,
                font=("Arial", 9),
                fg=self.fg_color,
                bg=self.bg_color,
                selectcolor=self.text_bg
            ).grid(row=i // 3, column=i % 3, sticky="w", padx=10, pady=5)
        
        # Buttons
        tk.Button(
            tab,
            text="▶ Start OSINT Gathering",
            font=("Arial", 11, "bold"),
            bg=self.button_color,
            fg=self.fg_color,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.start_osint,
            width=20
        ).pack(pady=10)
        
        # Results
        results_frame = tk.LabelFrame(
            tab,
            text="OSINT Results",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.osint_results_text = scrolledtext.ScrolledText(
            results_frame,
            font=("Consolas", 9),
            bg=self.text_bg,
            fg="#00ff00",
            insertbackground=self.fg_color,
            wrap=tk.WORD
        )
        self.osint_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_ai_analysis_tab(self):
        """Create AI analysis tab"""
        tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(tab, text="🤖 AI Analysis")
        
        # AI model selection
        config_frame = tk.LabelFrame(
            tab,
            text="AI Configuration",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        config_frame.pack(fill=tk.X, padx=20, pady=20)
        
        tk.Label(
            config_frame,
            text="AI Model:",
            font=("Arial", 10),
            fg=self.fg_color,
            bg=self.bg_color
        ).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.ai_model_var = tk.StringVar(value="llama3")
        models = ["llama3", "mistral", "deepseek-coder", "codellama"]
        
        model_combo = ttk.Combobox(
            config_frame,
            textvariable=self.ai_model_var,
            values=models,
            state="readonly",
            width=30
        )
        model_combo.grid(row=0, column=1, padx=10, pady=10)
        
        # AI Analysis results
        results_frame = tk.LabelFrame(
            tab,
            text="AI-Powered Vulnerability Analysis",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.ai_results_text = scrolledtext.ScrolledText(
            results_frame,
            font=("Consolas", 9),
            bg=self.text_bg,
            fg="#00ff00",
            insertbackground=self.fg_color,
            wrap=tk.WORD
        )
        self.ai_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Info
        info_text = """
AI Analysis provides:
• Intelligent vulnerability assessment
• CVE mapping and predictions
• CVSS scoring
• Exploitability ratings
• Detailed remediation recommendations
• Risk prioritization

Note: Requires Ollama or LM Studio running locally
        """
        
        self.ai_results_text.insert(tk.END, info_text)
    
    def create_reports_tab(self):
        """Create reports tab"""
        tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(tab, text="📊 Reports")
        
        # Report options
        options_frame = tk.LabelFrame(
            tab,
            text="Report Generation",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        options_frame.pack(fill=tk.X, padx=20, pady=20)
        
        tk.Button(
            options_frame,
            text="📄 Generate HTML Report",
            font=("Arial", 11),
            bg=self.button_color,
            fg=self.fg_color,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.generate_html_report,
            width=30
        ).pack(pady=10)
        
        tk.Button(
            options_frame,
            text="📑 Generate PDF Report",
            font=("Arial", 11),
            bg=self.button_color,
            fg=self.fg_color,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.generate_pdf_report,
            width=30
        ).pack(pady=10)
        
        tk.Button(
            options_frame,
            text="💾 Export as JSON",
            font=("Arial", 11),
            bg=self.button_color,
            fg=self.fg_color,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.export_json,
            width=30
        ).pack(pady=10)
        
        # Report preview
        preview_frame = tk.LabelFrame(
            tab,
            text="Report Preview",
            font=("Arial", 10, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.report_preview_text = scrolledtext.ScrolledText(
            preview_frame,
            font=("Consolas", 9),
            bg=self.text_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            wrap=tk.WORD
        )
        self.report_preview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def start_web_scan(self):
        """Start web vulnerability scan"""
        target = self.web_target_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        self.scan_running = True
        self.web_scan_button.config(state=tk.DISABLED)
        self.web_progress.start()
        self.web_results_text.delete(1.0, tk.END)
        self.update_status("Web scan in progress...")
        
        # Run scan in separate thread
        thread = threading.Thread(target=self._run_web_scan, args=(target,))
        thread.daemon = True
        thread.start()
    
    def _run_web_scan(self, target):
        """Run web scan in background thread"""
        try:
            self.log_message(f"Starting web scan on {target}")
            
            # Initialize scanner
            self.scanner = VulnerabilityScanner(ai_model=self.ai_model_var.get())
            
            # Run scan
            results = self.scanner.full_scan(target, {'web_scan': True, 'network_scan': False, 'osint_scan': False})
            
            self.scan_results = results
            
            # Display results
            self.root.after(0, self._display_web_results, results)
            
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Scan Error", str(e))
            logging.error(f"Web scan error: {e}")
        finally:
            self.scan_running = False
            self.root.after(0, self.web_progress.stop)
            self.root.after(0, lambda: self.web_scan_button.config(state=tk.NORMAL))
            self.root.after(0, self.update_status, "Scan complete")
    
    def _display_web_results(self, results):
        """Display web scan results"""
        text = self.web_results_text
        text.delete(1.0, tk.END)
        
        summary = results.get('summary', {})
        
        text.insert(tk.END, "="*80 + "\n")
        text.insert(tk.END, "WEB VULNERABILITY SCAN RESULTS\n")
        text.insert(tk.END, "="*80 + "\n\n")
        
        text.insert(tk.END, f"Target: {results.get('target')}\n")
        text.insert(tk.END, f"Scan Time: {results.get('scan_start')}\n")
        text.insert(tk.END, f"Duration: {results.get('scan_duration', 0):.2f} seconds\n\n")
        
        text.insert(tk.END, "SUMMARY:\n")
        text.insert(tk.END, f"  Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}\n")
        text.insert(tk.END, f"  Critical: {summary.get('critical_count', 0)}\n")
        text.insert(tk.END, f"  High: {summary.get('high_count', 0)}\n")
        text.insert(tk.END, f"  Medium: {summary.get('medium_count', 0)}\n")
        text.insert(tk.END, f"  Low: {summary.get('low_count', 0)}\n")
        text.insert(tk.END, f"  Risk Level: {summary.get('risk_level', 'Unknown')}\n\n")
        
        # Display vulnerabilities
        if results.get('vulnerabilities'):
            text.insert(tk.END, "\nVULNERABILITIES FOUND:\n")
            text.insert(tk.END, "-"*80 + "\n")
            
            for i, vuln in enumerate(results['vulnerabilities'][:20], 1):  # Show first 20
                text.insert(tk.END, f"\n[{i}] {vuln.get('type', 'Unknown')}\n")
                text.insert(tk.END, f"    URL: {vuln.get('url', 'N/A')}\n")
                text.insert(tk.END, f"    Parameter: {vuln.get('parameter', 'N/A')}\n")
                text.insert(tk.END, f"    Payload: {vuln.get('payload', 'N/A')}\n")
        
        self.log_message("Web scan completed successfully")
    
    def start_network_scan(self):
        """Start network scan"""
        target = self.network_target_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target host/IP")
            return
        
        self.update_status("Network scan in progress...")
        self.log_message(f"Starting network scan on {target}")
        
        # Run in thread
        thread = threading.Thread(target=self._run_network_scan, args=(target,))
        thread.daemon = True
        thread.start()
    
    def _run_network_scan(self, target):
        """Run network scan in background"""
        try:
            from core.port_scanner import PortScanner
            scanner = PortScanner()
            
            scan_all = (self.network_scan_type.get() == "full")
            results = scanner.scan_host(target, scan_all=scan_all)
            
            self.root.after(0, self._display_network_results, results)
            
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Scan Error", str(e))
            logging.error(f"Network scan error: {e}")
        finally:
            self.root.after(0, self.update_status, "Network scan complete")
    
    def _display_network_results(self, results):
        """Display network scan results"""
        text = self.network_results_text
        text.delete(1.0, tk.END)
        
        text.insert(tk.END, f"Network Scan Results for {results['host']}\n")
        text.insert(tk.END, "="*80 + "\n\n")
        
        text.insert(tk.END, f"Open Ports: {results['total_open']}\n\n")
        
        for port_info in results['open_ports']:
            text.insert(tk.END, f"Port {port_info['port']}: {port_info['service']}\n")
            if port_info.get('banner'):
                text.insert(tk.END, f"  Banner: {port_info['banner']}\n")
            text.insert(tk.END, "\n")
    
    def start_osint(self):
        """Start OSINT gathering"""
        target = self.osint_target_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target domain")
            return
        
        self.update_status("OSINT gathering in progress...")
        self.log_message(f"Starting OSINT on {target}")
        
        thread = threading.Thread(target=self._run_osint, args=(target,))
        thread.daemon = True
        thread.start()
    
    def _run_osint(self, target):
        """Run OSINT in background"""
        try:
            from core.osint import OSINTScanner
            scanner = OSINTScanner()
            
            results = scanner.gather_intelligence(target)
            
            self.root.after(0, self._display_osint_results, results)
            
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", str(e))
            logging.error(f"OSINT error: {e}")
        finally:
            self.root.after(0, self.update_status, "OSINT complete")
    
    def _display_osint_results(self, results):
        """Display OSINT results"""
        text = self.osint_results_text
        text.delete(1.0, tk.END)
        
        text.insert(tk.END, f"OSINT Results for {results['domain']}\n")
        text.insert(tk.END, "="*80 + "\n\n")
        
        # WHOIS
        if results.get('whois'):
            text.insert(tk.END, "WHOIS Information:\n")
            for k, v in results['whois'].items():
                if k != 'raw':
                    text.insert(tk.END, f"  {k}: {v}\n")
            text.insert(tk.END, "\n")
        
        # Subdomains
        if results.get('subdomains'):
            text.insert(tk.END, f"Subdomains Found ({len(results['subdomains'])}):\n")
            for sub in results['subdomains']:
                text.insert(tk.END, f"  - {sub}\n")
            text.insert(tk.END, "\n")
        
        # IP Info
        if results.get('ip_info'):
            text.insert(tk.END, "IP Geolocation:\n")
            for k, v in results['ip_info'].items():
                if k != 'error':
                    text.insert(tk.END, f"  {k}: {v}\n")
    
    def stop_scan(self):
        """Stop current scan"""
        self.scan_running = False
        self.update_status("Scan stopped")
        self.log_message("Scan stopped by user")
    
    def generate_html_report(self):
        """Generate HTML report"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results available. Please run a scan first.")
            return
        
        try:
            from reports.report_generator import ReportGenerator
            generator = ReportGenerator()
            
            filename = generator.generate_html_report(self.scan_results)
            
            messagebox.showinfo("Success", f"HTML report generated:\n{filename}")
            self.log_message(f"HTML report saved: {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {e}")
    
    def generate_pdf_report(self):
        """Generate PDF report"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results available. Please run a scan first.")
            return
        
        messagebox.showinfo("Info", "PDF generation feature coming soon!\nUse HTML report for now.")
    
    def export_json(self):
        """Export results as JSON"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results available.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            
            messagebox.showinfo("Success", f"Results exported to:\n{filename}")
    
    def new_scan(self):
        """Clear and prepare for new scan"""
        self.scan_results = None
        self.web_results_text.delete(1.0, tk.END)
        self.network_results_text.delete(1.0, tk.END)
        self.osint_results_text.delete(1.0, tk.END)
        self.update_status("Ready for new scan")
    
    def export_results(self):
        """Export current results"""
        self.export_json()
    
    def show_settings(self):
        """Show settings dialog"""
        messagebox.showinfo("Settings", "Settings panel coming soon!")
    
    def view_logs(self):
        """View application logs"""
        log_dir = Path("logs")
        messagebox.showinfo("Logs", f"Log files are located in:\n{log_dir.absolute()}")
    
    def show_docs(self):
        """Show documentation"""
        messagebox.showinfo("Documentation", "Documentation available in README.md")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
AI-VulnScanner PRO Max v1.0.0

Enterprise-level AI-powered cybersecurity vulnerability scanner

Features:
• Web vulnerability scanning
• Network port scanning
• OSINT intelligence gathering
• AI-powered analysis
• Comprehensive reporting

Powered by Free Local AI Models (Ollama/LM Studio)

© 2024 - Built with Python & Tkinter
        """
        messagebox.showinfo("About", about_text)
    
    def update_status(self, message: str):
        """Update status bar"""
        self.status_label.config(text=message)
    
    def log_message(self, message: str):
        """Log message"""
        logging.info(message)
    
    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def run(self):
        """Start the dashboard"""
        self.root.mainloop()


# Example usage
if __name__ == "__main__":
    dashboard = Dashboard("admin")
    dashboard.run()
