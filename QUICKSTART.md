# AI-VulnScanner PRO Max - Quick Start Guide

## 🚀 5-Minute Quick Start

### 1. Install Dependencies (2 minutes)

```powershell
pip install requests beautifulsoup4
```

### 2. Launch Application

```powershell
python main.py
```

### 3. Login

- Username: `admin`
- Password: `admin123`

### 4. Run First Scan

**Web Vulnerability Scan:**
1. Click **Web Scanner** tab
2. Enter target: `https://example.com`
3. Select scan options (all checked by default)
4. Click **▶ Start Web Scan**
5. Watch results in real-time

**Network Port Scan:**
1. Click **Network Scanner** tab
2. Enter target: `127.0.0.1` or any IP
3. Select scan type: Common Ports (Fast)
4. Click **▶ Start Network Scan**

**OSINT Gathering:**
1. Click **OSINT** tab
2. Enter domain: `example.com`
3. Check desired modules
4. Click **▶ Start OSINT Gathering**

### 5. Generate Report

1. After scan completes
2. Go to **Reports** tab
3. Click **📄 Generate HTML Report**
4. Report opens in browser automatically

---

## 🤖 Optional: Enable AI Features

### Install Ollama (5 minutes)

**Step 1: Download Ollama**
- Visit: https://ollama.ai
- Download for your OS
- Install (double-click installer)

**Step 2: Pull AI Model**

```powershell
ollama pull llama3
```

This downloads the LLaMA 3 8B model (~4.7GB)

**Step 3: Start Ollama**

```powershell
ollama serve
```

Or Ollama starts automatically on Windows/Mac

**Step 4: Verify in Scanner**
- Restart AI-VulnScanner
- Go to **AI Analysis** tab
- You should see: "✓ Ollama service is available"

### Alternative: LM Studio

1. Download from https://lmstudio.ai
2. Install and open
3. Download LLaMA 3 or Mistral model
4. Start local server
5. Scanner auto-detects running server

---

## 📋 Common Use Cases

### Security Audit Checklist

**Before Production Deployment:**

```
☐ Run full web vulnerability scan
☐ Check for SQL injection
☐ Test XSS protection
☐ Verify security headers
☐ Scan for exposed files
☐ Check SSL/TLS configuration
☐ Review AI recommendations
☐ Generate and review report
☐ Fix all Critical/High issues
☐ Rescan to verify fixes
```

### Bug Bounty Workflow

```
1. OSINT Gathering
   - Subdomain discovery
   - Technology fingerprinting
   - WAF detection

2. Web Scanning
   - Full vulnerability scan
   - Directory enumeration
   - Sensitive file discovery

3. Network Analysis
   - Port scanning
   - Service detection
   - SSL/TLS check

4. Manual Verification
   - Review AI analysis
   - Test exploitability
   - Document findings

5. Report Generation
   - Create detailed report
   - Add screenshots
   - Submit to program
```

---

## ⚙️ Configuration Tips

### Adjust Scan Speed

Edit timeout values in scanners:

```python
# In core/sql_injection.py
scanner = SQLInjectionScanner(timeout=10)  # Increase for slow servers

# In core/port_scanner.py
scanner = PortScanner(timeout=1.0, max_workers=100)  # Adjust threads
```

### Custom Payloads

Add your own payloads:

```python
# In core/sql_injection.py
ERROR_BASED_PAYLOADS = [
    "'",
    # Add your custom payload here
    "custom_payload_here"
]
```

### Enable Debug Logging

```python
# In main.py
logging.basicConfig(level=logging.DEBUG)  # Change from INFO to DEBUG
```

---

## 🐛 Troubleshooting

### "Module not found" errors

```powershell
pip install requests beautifulsoup4
```

### GUI not appearing

Check if Tkinter is installed:

```powershell
python -m tkinter
```

Should open a window. If not, reinstall Python with Tk support.

### Ollama connection failed

```powershell
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not, start Ollama
ollama serve
```

### Scans timing out

Increase timeout values or check network connection.

### "Permission denied" on port scan

Run as administrator on Windows or use sudo on Linux for ports < 1024.

---

## 💡 Pro Tips

1. **Start with Common Ports**: Use quick scan first, then full scan if needed

2. **Test in Staging**: Never scan production without permission

3. **Use AI Analysis**: Let AI prioritize findings by severity

4. **Regular Updates**: Keep payloads and signatures updated

5. **Combine Tools**: Use with other security tools for comprehensive testing

6. **Document Everything**: Export reports and keep scan history

7. **Rate Limiting**: Add delays between requests to avoid detection

8. **False Positives**: Always manually verify AI findings

9. **Backup First**: Backup target system before aggressive testing

10. **Stay Legal**: Only scan systems you own or have permission for

---

## 📚 Next Steps

- Read full **README.md** for detailed documentation
- Explore **core/** directory for scanner internals
- Customize payloads for your needs
- Join community discussions
- Star the project on GitHub ⭐

---

**Happy Scanning! 🛡️**

For questions: Check FAQ in README.md
For issues: GitHub Issues
For updates: Watch the repository
