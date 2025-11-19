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
 * Monitor scan progress
 */
function monitorProgress() {
    if (!currentSessionId) return;
    
    progressInterval = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE}/api/scan/status/${currentSessionId}`);
            const data = await response.json();
            
            if (!data.success) {
                throw new Error(data.error || 'Failed to get status');
            }
            
            // Update progress bar
            const progress = data.progress || 0;
            document.getElementById('progressBar').style.width = progress + '%';
            document.getElementById('progressText').textContent = progress + '%';
            
            // Update status
            document.getElementById('statusDisplay').textContent = data.status;
            document.getElementById('progressMessage').textContent = data.message || 'Processing...';
            
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
            console.error('Progress check failed:', error);
            clearInterval(progressInterval);
            showToast('Lost connection to scan', 'error');
        }
    }, 1000); // Check every second
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
 * Display scan results
 */
function displayResults(results) {
    const summaryDiv = document.getElementById('resultsSummary');
    if (!summaryDiv || !results) return;
    
    const stats = results.statistics || {};
    const vulns = results.vulnerabilities || [];
    
    summaryDiv.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px;">
            <div class="stat-card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 15px; text-align: center;">
                <div style="font-size: 3em; font-weight: bold;">${stats.total_vulnerabilities || 0}</div>
                <div style="font-size: 1.1em;">Total Vulnerabilities</div>
            </div>
            
            <div class="stat-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 25px; border-radius: 15px; text-align: center;">
                <div style="font-size: 3em; font-weight: bold;">${stats.critical || 0}</div>
                <div style="font-size: 1.1em;">Critical</div>
            </div>
            
            <div class="stat-card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; padding: 25px; border-radius: 15px; text-align: center;">
                <div style="font-size: 3em; font-weight: bold;">${stats.high || 0}</div>
                <div style="font-size: 1.1em;">High</div>
            </div>
            
            <div class="stat-card" style="background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); color: #333; padding: 25px; border-radius: 15px; text-align: center;">
                <div style="font-size: 3em; font-weight: bold;">${stats.medium || 0}</div>
                <div style="font-size: 1.1em;">Medium</div>
            </div>
            
            <div class="stat-card" style="background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); color: #333; padding: 25px; border-radius: 15px; text-align: center;">
                <div style="font-size: 3em; font-weight: bold;">${stats.low || 0}</div>
                <div style="font-size: 1.1em;">Low</div>
            </div>
        </div>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
            <h3 style="color: #667eea; margin-bottom: 15px;">📊 Scan Statistics</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <div>
                    <strong>Endpoints Tested:</strong> ${stats.total_endpoints || 0}
                </div>
                <div>
                    <strong>Forms Found:</strong> ${stats.total_forms || 0}
                </div>
                <div>
                    <strong>Open Ports:</strong> ${stats.open_ports || 0}
                </div>
                <div>
                    <strong>Technologies:</strong> ${stats.technologies_detected || 0}
                </div>
            </div>
        </div>
        
        ${results.ai_summary ? `
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 15px; margin-bottom: 20px;">
                <h3 style="margin-bottom: 15px;">🤖 AI Executive Summary</h3>
                <p style="line-height: 1.8; white-space: pre-wrap;">${results.ai_summary}</p>
            </div>
        ` : ''}
        
        <div style="background: white; padding: 25px; border-radius: 15px; border: 2px solid #e1e4e8;">
            <h3 style="color: #667eea; margin-bottom: 15px;">🔍 Top Vulnerabilities</h3>
            ${vulns.slice(0, 5).map(v => `
                <div style="padding: 15px; background: #f8f9fa; border-radius: 10px; margin-bottom: 10px; border-left: 4px solid ${getSeverityColor(v.severity)};">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <strong style="font-size: 1.1em;">${v.type || 'Unknown'}</strong>
                        <span style="background: ${getSeverityColor(v.severity)}; color: white; padding: 5px 15px; border-radius: 20px; font-size: 0.9em; font-weight: bold;">
                            ${(v.severity || 'Low').toUpperCase()}
                        </span>
                    </div>
                    <div style="color: #666; margin-bottom: 5px;">${v.details || 'No details'}</div>
                    <div style="font-family: 'Courier New', monospace; font-size: 0.85em; color: #888;">
                        📍 ${v.location || 'Unknown location'}
                    </div>
                </div>
            `).join('')}
            ${vulns.length > 5 ? `<p style="text-align: center; color: #666; margin-top: 15px;">...and ${vulns.length - 5} more vulnerabilities</p>` : ''}
            ${vulns.length === 0 ? `
                <div style="text-align: center; padding: 20px;">
                    <div style="font-size: 3em; color: #28a745;">✅</div>
                    <h3 style="color: #28a745; margin: 15px 0;">No Critical Vulnerabilities Detected!</h3>
                    <p style="color: #666;">The target appears to be well-secured. However, this doesn't guarantee complete security.</p>
                </div>
            ` : ''}
        </div>
        
        ${results.scan_coverage ? `
            <div style="background: #f0f9ff; padding: 25px; border-radius: 15px; border: 2px solid #0ea5e9; margin-top: 20px;">
                <h3 style="color: #0369a1; margin-bottom: 15px;">🔬 Scan Coverage</h3>
                <div style="margin-bottom: 15px;">
                    <strong>URLs Tested:</strong> ${results.scan_coverage.urls_tested || 0}<br>
                    <strong>Forms Analyzed:</strong> ${results.scan_coverage.forms_analyzed || 0}<br>
                    <strong>Ports Scanned:</strong> ${results.scan_coverage.ports_scanned || 'Common ports'}
                </div>
                <div style="background: white; padding: 15px; border-radius: 10px;">
                    <strong style="color: #0369a1;">Tests Performed:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px; columns: 2;">
                        ${(results.scan_coverage.tests_performed || []).map(test => `<li>${test}</li>`).join('')}
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
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745'
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
