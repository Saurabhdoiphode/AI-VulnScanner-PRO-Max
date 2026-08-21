/**
 * AI-VulnScanner PRO Max - Scan Page JavaScript
 * Handles scan execution and real-time progress monitoring
 */

let currentSessionId = null;
let progressInterval = null;

/**
 * Start a new scan
 */
async function startScan() {
    const target = document.getElementById('scanTarget').value.trim();
    
    // Validate input
    if (!target) {
        showToast('Please enter a target URL or IP address', 'error');
        return;
    }
    
    if (!isValidUrl(target)) {
        showToast('Invalid URL format. Use https://example.com or IP address', 'error');
        return;
    }
    
    const scanTypes = getSelectedScanTypes();
    if (scanTypes.length === 0) {
        showToast('Please select at least one scan type', 'error');
        return;
    }
    
    const aiModel = getSelectedAIModel();
    
    // Show progress view
    document.getElementById('scanConfig').style.display = 'none';
    document.getElementById('scanProgress').style.display = 'block';
    document.getElementById('progressTarget').textContent = target;
    
    // Start scan
    try {
        showToast('Starting scan...', 'info');
        
        const response = await fetch(`${API_BASE}/api/scan/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                scan_types: scanTypes,
                ai_model: aiModel
            })
        });
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Failed to start scan');
        }
        
        currentSessionId = data.session_id;
        document.getElementById('sessionIdDisplay').textContent = currentSessionId;
        
        showToast('Scan started successfully!', 'success');
        
        // Start monitoring progress
        monitorProgress();
        
    } catch (error) {
        console.error('Scan start failed:', error);
        showToast('Failed to start scan: ' + error.message, 'error');
        resetScan();
    }
}

/**
 * Monitor scan progress with Unlimited Resilient Retries (No disconnection drops)
 */
let errorCount = 0;
function monitorProgress() {
    if (!currentSessionId) return;
    errorCount = 0;
    
    progressInterval = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE}/api/scan/status/${currentSessionId}`);
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            const data = await response.json();
            
            if (!data.success) {
                throw new Error(data.error || 'Failed to get status');
            }
            
            // Reset error count on successful status check
            if (errorCount > 0) {
                errorCount = 0;
                document.getElementById('statusDisplay').textContent = data.status || 'Scanning...';
            }
            
            // Update progress bar
            const progress = data.progress || 0;
            document.getElementById('progressBar').style.width = progress + '%';
            document.getElementById('progressText').textContent = progress + '%';
            
            // Update status
            document.getElementById('statusDisplay').textContent = data.status;
            document.getElementById('progressMessage').textContent = data.message || 'Deep scanning target...';
            
            if (data.start_time) {
                document.getElementById('startTimeDisplay').textContent = formatDateTime(data.start_time);
            }
            
            // Add log entry
            addLogEntry(data.message, progress);
            
            // Check if scan is complete
            if (data.status === 'completed') {
                clearInterval(progressInterval);
                onScanComplete();
            } else if (data.status === 'failed') {
                clearInterval(progressInterval);
                showToast('Scan failed: ' + (data.error || 'Unknown error'), 'error');
                setTimeout(resetScan, 3000);
            }
            
        } catch (error) {
            errorCount++;
            console.warn(`Reconnecting to scanner stream (${errorCount})...`, error);
            document.getElementById('statusDisplay').textContent = 'Reconnecting...';
            // Infinite silent reconnect mode for heavy background scans
        }
    }, 1500);
}

/**
 * Add entry to live log
 */
function addLogEntry(message, progress) {
    const logContent = document.getElementById('logContent');
    if (!logContent) return;
    
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.style.cssText = `
        padding: 8px 12px;
        border-left: 3px solid #667eea;
        background: #f8f9fa;
        margin-bottom: 8px;
        border-radius: 5px;
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
    `;
    
    const timestamp = new Date().toLocaleTimeString();
    entry.innerHTML = `
        <span style="color: #666;">[${timestamp}]</span>
        <span style="color: #667eea; font-weight: bold;">[${progress}%]</span>
        <span style="color: #333;">${message}</span>
    `;
    
    logContent.appendChild(entry);
    
    // Auto-scroll to bottom
    logContent.scrollTop = logContent.scrollHeight;
    
    // Keep only last 50 entries
    while (logContent.children.length > 50) {
        logContent.removeChild(logContent.firstChild);
    }
}

/**
 * Handle scan completion
 */
async function onScanComplete() {
    showToast('Scan completed successfully!', 'success');
    
    try {
        // Fetch results
        const response = await fetch(`${API_BASE}/api/scan/results/${currentSessionId}`);
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Failed to get results');
        }
        
        // Display results
        displayResults(data.results);
        
        // Show results view
        document.getElementById('scanProgress').style.display = 'none';
        document.getElementById('scanResults').style.display = 'block';
        
    } catch (error) {
        console.error('Failed to load results:', error);
        showToast('Failed to load results: ' + error.message, 'error');
    }
}

/**
 * Display scan results with High-Contrast Cyber Dark Glassmorphism
 */
function displayResults(results) {
    const summaryDiv = document.getElementById('resultsSummary');
    if (!summaryDiv || !results) return;
    
    const stats = results.statistics || {};
    const vulns = results.vulnerabilities || [];
    
    summaryDiv.innerHTML = `
        <!-- High Contrast Stat Cards -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 18px; margin-bottom: 30px;">
            <div class="stat-card" style="background: rgba(15, 23, 42, 0.95); border: 1px solid var(--primary-cyan); color: #ffffff; padding: 22px; border-radius: 18px; text-align: center; box-shadow: var(--glow-cyan);">
                <div style="font-size: 2.8em; font-weight: 800; color: var(--primary-cyan);">${stats.total_vulnerabilities || vulns.length || 0}</div>
                <div style="font-size: 0.95em; font-weight: 700; color: #e2e8f0;">Total Vulnerabilities</div>
            </div>
            
            <div class="stat-card" style="background: rgba(15, 23, 42, 0.95); border: 1px solid #ff0055; color: #ffffff; padding: 22px; border-radius: 18px; text-align: center; box-shadow: 0 0 20px rgba(255, 0, 85, 0.4);">
                <div style="font-size: 2.8em; font-weight: 800; color: #ff0055;">${stats.critical || 0}</div>
                <div style="font-size: 0.95em; font-weight: 700; color: #e2e8f0;">Critical</div>
            </div>
            
            <div class="stat-card" style="background: rgba(15, 23, 42, 0.95); border: 1px solid #ff7700; color: #ffffff; padding: 22px; border-radius: 18px; text-align: center; box-shadow: 0 0 20px rgba(255, 119, 0, 0.4);">
                <div style="font-size: 2.8em; font-weight: 800; color: #ff7700;">${stats.high || 0}</div>
                <div style="font-size: 0.95em; font-weight: 700; color: #e2e8f0;">High</div>
            </div>
            
            <div class="stat-card" style="background: rgba(15, 23, 42, 0.95); border: 1px solid #ffcf00; color: #ffffff; padding: 22px; border-radius: 18px; text-align: center; box-shadow: 0 0 20px rgba(255, 207, 0, 0.4);">
                <div style="font-size: 2.8em; font-weight: 800; color: #ffcf00;">${stats.medium || 0}</div>
                <div style="font-size: 0.95em; font-weight: 700; color: #e2e8f0;">Medium</div>
            </div>
            
            <div class="stat-card" style="background: rgba(15, 23, 42, 0.95); border: 1px solid #00ff87; color: #ffffff; padding: 22px; border-radius: 18px; text-align: center; box-shadow: 0 0 20px rgba(0, 255, 135, 0.4);">
                <div style="font-size: 2.8em; font-weight: 800; color: #00ff87;">${stats.low || 0}</div>
                <div style="font-size: 0.95em; font-weight: 700; color: #e2e8f0;">Low</div>
            </div>
        </div>
        
        <!-- Scan Statistics Panel -->
        <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(0, 242, 254, 0.3); padding: 22px; border-radius: 18px; margin-bottom: 25px; color: #f8fafc; text-align: left;">
            <h3 style="color: var(--primary-cyan); font-size: 1.25rem; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
                <span>📊</span> Scan Execution Statistics
            </h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <div style="background: rgba(30, 41, 59, 0.7); padding: 12px 18px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
                    <strong style="color: var(--text-muted); display: block; font-size: 0.85rem;">Endpoints Tested:</strong>
                    <span style="font-size: 1.2rem; font-weight: 700; color: #ffffff;">${stats.total_endpoints || (results.endpoints ? results.endpoints.length : 0) || 1}</span>
                </div>
                <div style="background: rgba(30, 41, 59, 0.7); padding: 12px 18px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
                    <strong style="color: var(--text-muted); display: block; font-size: 0.85rem;">Forms Analyzed:</strong>
                    <span style="font-size: 1.2rem; font-weight: 700; color: #ffffff;">${stats.total_forms || (results.forms ? results.forms.length : 0) || 0}</span>
                </div>
                <div style="background: rgba(30, 41, 59, 0.7); padding: 12px 18px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
                    <strong style="color: var(--text-muted); display: block; font-size: 0.85rem;">Open Ports:</strong>
                    <span style="font-size: 1.2rem; font-weight: 700; color: #ffffff;">${stats.open_ports || (results.open_ports ? results.open_ports.length : 0) || 0}</span>
                </div>
                <div style="background: rgba(30, 41, 59, 0.7); padding: 12px 18px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
                    <strong style="color: var(--text-muted); display: block; font-size: 0.85rem;">Technologies:</strong>
                    <span style="font-size: 1.2rem; font-weight: 700; color: #ffffff;">${stats.technologies_detected || (results.technologies ? results.technologies.length : 0) || 0}</span>
                </div>
            </div>
        </div>
        
        <!-- AI Summary Panel -->
        ${results.ai_summary ? `
            <div style="background: linear-gradient(135deg, rgba(157, 80, 187, 0.3) 0%, rgba(0, 242, 254, 0.2) 100%); border: 1px solid var(--primary-purple); color: #ffffff; padding: 25px; border-radius: 18px; margin-bottom: 25px; box-shadow: var(--glow-purple); text-align: left;">
                <h3 style="color: #ffffff; font-size: 1.3rem; margin-bottom: 14px; display: flex; align-items: center; gap: 8px;">
                    <span>🤖</span> AI Executive Summary
                </h3>
                <p style="line-height: 1.8; white-space: pre-wrap; color: #f1f5f9; font-size: 1rem;">${results.ai_summary}</p>
            </div>
        ` : ''}
        
        <!-- Top Vulnerabilities Panel -->
        <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(0, 242, 254, 0.3); padding: 28px; border-radius: 20px; text-align: left;">
            <h3 style="color: var(--primary-cyan); font-size: 1.35rem; font-weight: 700; margin-bottom: 20px; display: flex; align-items: center; gap: 8px;">
                <span>🔍</span> Vulnerabilities Detected (${vulns.length})
            </h3>
            
            ${vulns.map((v, index) => `
                <div style="padding: 20px; background: rgba(30, 41, 59, 0.75); border-radius: 14px; margin-bottom: 16px; border-left: 5px solid ${getSeverityColor(v.severity)}; border-top: 1px solid rgba(255,255,255,0.08); border-right: 1px solid rgba(255,255,255,0.08); border-bottom: 1px solid rgba(255,255,255,0.08);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
                        <strong style="font-size: 1.15rem; color: #ffffff; font-weight: 700;">${index + 1}. ${v.type || v.title || 'Security Issue'}</strong>
                        <span style="background: ${getSeverityColor(v.severity)}; color: #070a13; padding: 6px 16px; border-radius: 20px; font-size: 0.85rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 0 12px ${getSeverityColor(v.severity)};">
                            ${(v.severity || 'Low').toUpperCase()}
                        </span>
                    </div>
                    
                    <div style="color: #cbd5e1; font-size: 0.98rem; line-height: 1.6; margin-bottom: 12px;">
                        ${v.details || v.description || 'Vulnerability detected during scan.'}
                    </div>
                    
                    <div style="display: flex; gap: 15px; flex-wrap: wrap; font-family: 'Fira Code', monospace; font-size: 0.85rem; color: var(--primary-cyan); background: rgba(15, 23, 42, 0.85); padding: 10px 14px; border-radius: 8px; border: 1px solid rgba(0, 242, 254, 0.2);">
                        <div>📍 <span style="color: #94a3b8;">URL:</span> <span style="color: #ffffff;">${v.location || v.url || results.target || 'N/A'}</span></div>
                        ${v.method ? `<div>⚡ <span style="color: #94a3b8;">Method:</span> <span style="color: #ffffff;">${v.method}</span></div>` : ''}
                        ${v.parameter ? `<div>🔑 <span style="color: #94a3b8;">Param:</span> <span style="color: #ffffff;">${v.parameter}</span></div>` : ''}
                    </div>
                </div>
            `).join('')}
            
            ${vulns.length === 0 ? `
                <div style="text-align: center; padding: 35px 20px; background: rgba(30, 41, 59, 0.4); border-radius: 16px; border: 1px dashed rgba(0, 255, 135, 0.4);">
                    <div style="font-size: 3.5em; color: var(--neon-green); margin-bottom: 10px;">✅</div>
                    <h3 style="color: var(--neon-green); font-size: 1.4rem; margin-bottom: 8px;">No High-Risk Vulnerabilities Detected!</h3>
                    <p style="color: #94a3b8; font-size: 0.95rem;">The target endpoints passed standard vulnerability checks cleanly.</p>
                </div>
            ` : ''}
        </div>
        
        <!-- Scan Coverage Panel -->
        ${results.scan_coverage ? `
            <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(0, 242, 254, 0.3); padding: 28px; border-radius: 20px; margin-top: 25px; text-align: left;">
                <h3 style="color: var(--primary-cyan); font-size: 1.3rem; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
                    <span>🔬</span> Scan Scope & Coverage
                </h3>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                    <div style="color: #f1f5f9; font-size: 0.95rem;">
                        <strong style="color: var(--text-muted);">URLs Tested:</strong> <span style="color: #ffffff; font-weight: 700;">${results.scan_coverage.urls_tested || 1}</span>
                    </div>
                    <div style="color: #f1f5f9; font-size: 0.95rem;">
                        <strong style="color: var(--text-muted);">Forms Analyzed:</strong> <span style="color: #ffffff; font-weight: 700;">${results.scan_coverage.forms_analyzed || 0}</span>
                    </div>
                    <div style="color: #f1f5f9; font-size: 0.95rem;">
                        <strong style="color: var(--text-muted);">Ports Scanned:</strong> <span style="color: #ffffff; font-weight: 700;">${results.scan_coverage.ports_scanned || 'Common ports (21,22,80,443,etc)'}</span>
                    </div>
                </div>
                
                <div style="background: rgba(30, 41, 59, 0.7); padding: 20px; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
                    <strong style="color: var(--primary-cyan); display: block; margin-bottom: 12px; font-size: 1rem;">Tests Performed:</strong>
                    <ul style="margin: 0; padding-left: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; color: #f1f5f9; font-size: 0.92rem;">
                        ${(results.scan_coverage.tests_performed || [
                            'SQL Injection', 'Cross-Site Scripting (XSS)', 'Server-Side Template Injection (SSTI)',
                            'Command Injection', 'Path Traversal', 'Open Redirect', 'File Upload Vulnerabilities',
                            'Security Headers Analysis', 'Sensitive File Discovery', 'Port Scanning', 'SSL/TLS Analysis', 'OSINT Recon'
                        ]).map(test => `<li style="color: #e2e8f0;">${test}</li>`).join('')}
                    </ul>
                </div>
            </div>
        ` : ''}
    `;
}

/**
 * Get color for severity level
 */
function getSeverityColor(severity) {
    const colors = {
        'Critical': '#ff0055',
        'High': '#ff7700',
        'Medium': '#ffcf00',
        'Low': '#00ff87'
    };
    return colors[severity] || colors['Low'];
}

/**
 * Download report
 */
async function downloadReport(format) {
    if (!currentSessionId) {
        showToast('No scan session available', 'error');
        return;
    }
    
    try {
        showToast(`Generating ${format.toUpperCase()} report...`, 'info');
        
        const url = `${API_BASE}/api/report/${format}/${currentSessionId}`;
        
        // Use fetch to get the report with proper error handling
        const response = await fetch(url);
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(errorData.error || `Server error: ${response.status}`);
        }
        
        // Get the blob data
        const blob = await response.blob();
        
        // Create download link and trigger download
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = downloadUrl;
        a.download = `report_${currentSessionId}.${format}`;
        
        document.body.appendChild(a);
        a.click();
        
        // Cleanup
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
        
        showToast('Report downloaded successfully!', 'success');
        
    } catch (error) {
        console.error('Report download failed:', error);
        showToast('Failed to download report: ' + error.message, 'error');
    }
}

/**
 * View report in browser
 */
function viewReport() {
    if (!currentSessionId) {
        showToast('No scan session available', 'error');
        return;
    }
    
    window.open(`${API_BASE}/report/${currentSessionId}`, '_blank');
}

/**
 * Reset scan and show configuration again
 */
function resetScan() {
    // Clear session
    currentSessionId = null;
    
    // Clear interval
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
    
    // Reset progress
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressText').textContent = '0%';
    document.getElementById('logContent').innerHTML = '';
    
    // Show config view
    document.getElementById('scanResults').style.display = 'none';
    document.getElementById('scanProgress').style.display = 'none';
    document.getElementById('scanConfig').style.display = 'block';
    
    // Scroll to top
    window.scrollTo(0, 0);
}
