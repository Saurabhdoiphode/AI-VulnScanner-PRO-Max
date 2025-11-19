# 🛡️ AI-VulnScanner PRO Max - Complete Installation & Usage Guide

## 🎯 What You Have Now

You now have **TWO complete applications**:

### 1️⃣ Desktop Application (Tkinter GUI)
- **Location**: `desktop_app/`
- **Run**: `python desktop_app/main.py`
- **Features**: Full GUI, local scanning, offline operation

### 2️⃣ Web Application (Flask Web Interface)
- **Location**: `web_app/`
- **Run**: `python web_app/app.py`
- **Features**: Browser-based, RESTful API, multi-user support

Both share the same powerful **`shared_core/`** scanning engine!

---

## 🚀 Quick Start (Choose One)

### Option A: Desktop App

```bash
# Step 1: Install dependencies
pip install requests beautifulsoup4

# Step 2: Run
python desktop_app/main.py

# Step 3: Login
Username: admin
Password: admin123
```

### Option B: Web App

```bash
# Step 1: Install dependencies
pip install flask flask-cors requests beautifulsoup4

# Step 2: Run server
python web_app/app.py

# Step 3: Open browser
http://localhost:5000
```

---

## 🤖 Enable AI Features (Optional but Recommended)

```bash
# 1. Install Ollama
Visit: https://ollama.ai
Download and install for your OS

# 2. Pull AI model
ollama pull llama3

# 3. Verify (should return model list)
curl http://localhost:11434/api/tags
```

**AI Models Available:**
- `llama3` - 4.7GB - **Recommended** - Best overall
- `mistral` - 4.1GB - Fast scans
- `deepseek-coder` - 4.5GB - Code analysis specialist
- `codellama` - 3.8GB - Lightweight option

---

## 📚 Full Documentation

See [FULL_README.md](FULL_README.md) for comprehensive documentation including:
- Complete feature list (50+ tests)
- API documentation
- Advanced configuration
- Troubleshooting guide
- FAQ
- Contributing guidelines

---

## ✨ Key Features

### Web Vulnerabilities (15+ tests)
✅ SQL Injection (Error, Boolean, Time-based)
✅ XSS (Reflective, Stored, DOM)
✅ SSTI (7 template engines)
✅ Command Injection
✅ Path Traversal & LFI
✅ Open Redirects
✅ File Upload Vulnerabilities
✅ Security Headers
✅ CORS Misconfiguration
✅ Sensitive File Discovery

### Network Scanning
✅ Port Scanning (1-65535)
✅ Service Detection
✅ SSL/TLS Analysis
✅ Banner Grabbing

### OSINT Intelligence
✅ WHOIS Lookup
✅ DNS Records
✅ Subdomain Discovery
✅ IP Geolocation

### AI Analysis
✅ Intelligent vulnerability assessment
✅ CVE prediction
✅ CVSS scoring
✅ Remediation recommendations
✅ Executive summaries

---

## 📁 Project Structure

```
Web Scanner/
│
├── desktop_app/          # Desktop GUI Application
│   ├── main.py          # Entry point
│   ├── gui/             # Tkinter interfaces
│   ├── core/            # Desktop scanners
│   └── requirements.txt
│
├── web_app/             # Web Application
│   ├── app.py           # Flask server
│   ├── templates/       # HTML pages
│   ├── static/          # CSS/JS
│   └── requirements.txt
│
├── shared_core/         # Shared Engine (used by both)
│   ├── ai_engine.py    # AI integration
│   ├── scanner.py      # Main orchestrator
│   ├── report_generator.py
│   └── file_upload_test.py
│
├── core/                # Original Scanner Modules
│   ├── sql_injection.py
│   ├── xss_scanner.py
│   ├── ssti_scanner.py
│   ├── cmd_injection.py
│   ├── path_traversal.py
│   ├── open_redirect.py
│   ├── header_scanner.py
│   ├── directory_finder.py
│   ├── tech_fingerprint.py
│   ├── port_scanner.py
│   ├── ssl_checker.py
│   ├── osint.py
│   └── crawler.py
│
└── reports/             # Generated reports
    └── output/
```

---

## 🎓 Usage Examples

### Desktop App - Web Scan
1. Launch: `python desktop_app/main.py`
2. Login: `admin` / `admin123`
3. Go to "Web Scanner" tab
4. Enter: `https://example.com`
5. Click "Start Web Scan"
6. View results and generate report

### Web App - API Usage
```bash
# Start scan
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "scan_types": ["web", "network", "osint", "ai"],
    "ai_model": "llama3"
  }'

# Returns: {"success": true, "session_id": "abc123..."}

# Check status
curl http://localhost:5000/api/scan/status/abc123

# Download report
curl http://localhost:5000/api/report/html/abc123 -o report.html
```

---

## ⚠️ Legal Warning

**THIS TOOL IS FOR AUTHORIZED TESTING ONLY!**

❌ **DO NOT** scan systems without permission
✅ **DO** only test your own systems or with explicit authorization
✅ **DO** use for educational purposes
✅ **DO** report findings responsibly

**Unauthorized scanning is ILLEGAL and punishable by law.**

The developers assume **NO responsibility** for misuse.

---

## 🐛 Common Issues

### "Module not found"
```bash
pip install requests beautifulsoup4 flask flask-cors
```

### "Tkinter not available" (Desktop)
- **Windows/Mac**: Reinstall Python with Tk support
- **Ubuntu**: `sudo apt-get install python3-tk`

### "Ollama connection failed"
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not, start it
ollama serve
```

### Web app won't start
```bash
# Check if port 5000 is available
# Or change port in web_app/app.py:
app.run(port=8080)
```

---

## 📊 What's Included

**Desktop Application:**
- ✅ Tkinter GUI with dark theme
- ✅ Login system (SQLite)
- ✅ 5 tabs: Web, Network, OSINT, AI, Reports
- ✅ Real-time progress bars
- ✅ Threaded scanning (non-blocking UI)
- ✅ HTML/JSON report generation

**Web Application:**
- ✅ Modern responsive design
- ✅ Live progress monitoring
- ✅ RESTful API
- ✅ Session management
- ✅ Multiple concurrent scans
- ✅ Beautiful gradient UI

**Shared Core:**
- ✅ 16 scanner modules
- ✅ AI engine with 4 model support
- ✅ Professional HTML reports
- ✅ File upload vulnerability tester
- ✅ Comprehensive orchestrator

**Original Scanners:**
- ✅ 13 specialized scanner modules
- ✅ Web crawler
- ✅ All major vulnerability types
- ✅ Network & OSINT capabilities

---

## 💡 Tips

1. **Start Simple**: Try web app first - easier to get started
2. **Use AI**: Install Ollama for intelligent analysis
3. **Test Locally**: Try scanning `http://localhost` first
4. **Read Logs**: Check `desktop_app/logs/` or console output
5. **Customize**: Edit scanner modules to add your own tests

---

## 🌟 Next Steps

1. **Run Both Apps**: Try desktop GUI and web interface
2. **Install AI**: Get Ollama and LLaMA 3 for best results
3. **Read Full Docs**: See FULL_README.md for advanced features
4. **Customize**: Add your own payloads and tests
5. **Contribute**: Star the project and submit PRs!

---

## 📞 Support

- **Quick Start**: This file (GETTING_STARTED.md)
- **Full Documentation**: FULL_README.md
- **Quick Reference**: QUICKSTART.md
- **Issues**: Report bugs on GitHub
- **Questions**: Check FAQ in documentation

---

<div align="center">

### 🎉 You're Ready to Start Scanning! 🎉

**Choose your interface and start your first scan now!**

**Made with ❤️ using FREE local AI • No cloud • 100% Privacy**

</div>
