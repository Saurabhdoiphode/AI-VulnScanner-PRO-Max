# AI-VulnScanner PRO Max - Installation & Setup Script
# Run this script for automated setup

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "║          AI-VulnScanner PRO Max - Setup Wizard               ║" -ForegroundColor Cyan
Write-Host "║          Version 1.0.0                                       ║" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check Python version
Write-Host "[1/5] Checking Python installation..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Python found: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "  ✗ Python not found! Please install Python 3.8 or higher." -ForegroundColor Red
    Write-Host "  Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Check pip
Write-Host "[2/5] Checking pip..." -ForegroundColor Yellow
$pipVersion = pip --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ pip found: $pipVersion" -ForegroundColor Green
} else {
    Write-Host "  ✗ pip not found! Installing pip..." -ForegroundColor Red
    python -m ensurepip --upgrade
}

# Install requirements
Write-Host "[3/5] Installing Python dependencies..." -ForegroundColor Yellow
Write-Host "  Installing: requests, beautifulsoup4" -ForegroundColor Cyan

pip install -q requests beautifulsoup4

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Dependencies installed successfully" -ForegroundColor Green
} else {
    Write-Host "  ✗ Error installing dependencies" -ForegroundColor Red
    Write-Host "  Try: pip install -r requirements.txt" -ForegroundColor Yellow
}

# Create directories
Write-Host "[4/5] Creating directory structure..." -ForegroundColor Yellow
$directories = @("reports/output", "reports/templates", "database", "logs", "core", "gui")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  ✓ Created: $dir" -ForegroundColor Green
    } else {
        Write-Host "  ✓ Exists: $dir" -ForegroundColor Gray
    }
}

# Check for Ollama
Write-Host "[5/5] Checking AI integration (Ollama)..." -ForegroundColor Yellow
try {
    $ollamaTest = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -TimeoutSec 3 -ErrorAction SilentlyContinue
    Write-Host "  ✓ Ollama is running!" -ForegroundColor Green
    Write-Host "  AI-powered analysis will be available" -ForegroundColor Cyan
} catch {
    Write-Host "  ⚠ Ollama not detected (Optional)" -ForegroundColor Yellow
    Write-Host "  The scanner will work without AI features" -ForegroundColor Gray
    Write-Host "  To enable AI: Install Ollama from https://ollama.ai" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✓ Installation Complete!" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Quick Start:" -ForegroundColor Yellow
Write-Host "  1. Run: python main.py" -ForegroundColor White
Write-Host "  2. Login with: admin / admin123" -ForegroundColor White
Write-Host "  3. Start scanning!" -ForegroundColor White
Write-Host ""
Write-Host "Optional - Enable AI Features:" -ForegroundColor Yellow
Write-Host "  1. Install Ollama: https://ollama.ai" -ForegroundColor White
Write-Host "  2. Run: ollama pull llama3" -ForegroundColor White
Write-Host "  3. Run: ollama serve" -ForegroundColor White
Write-Host ""
Write-Host "Documentation: README.md" -ForegroundColor Cyan
Write-Host "Support: https://github.com/yourusername/ai-vulnscanner-pro" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Enter to launch the application..." -ForegroundColor Yellow
Read-Host

# Launch application
python main.py
