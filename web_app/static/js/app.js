/**
 * AI-VulnScanner PRO Max - Main JavaScript
 * Handles API communication and UI interactions
 */

// API Base URL
const API_BASE = window.location.origin;

/**
 * Check if AI service is available
 */
async function checkAIAvailability() {
    const statusDiv = document.getElementById('aiStatus');
    if (!statusDiv) return;
    
    try {
        const response = await fetch(`${API_BASE}/api/ai/check`);
        const data = await response.json();
        
        if (data.available) {
            statusDiv.className = 'ai-status available';
            statusDiv.innerHTML = `
                <div style="display: flex; align-items: center; justify-content: center; gap: 10px;">
                    <span style="font-size: 1.5em;">✅</span>
                    <div>
                        <strong>AI Service Active</strong>
                        <p style="margin: 5px 0 0 0; opacity: 0.9;">
                            ${Object.keys(data.models).length} models available: 
                            ${Object.keys(data.models).join(', ')}
                        </p>
                    </div>
                </div>
            `;
        } else {
            statusDiv.className = 'ai-status unavailable';
            statusDiv.innerHTML = `
                <div style="display: flex; align-items: center; justify-content: center; gap: 10px;">
                    <span style="font-size: 1.5em;">⚠️</span>
                    <div>
                        <strong>AI Service Unavailable</strong>
                        <p style="margin: 5px 0 0 0; opacity: 0.9;">
                            Scanner will work with rule-based analysis. 
                            <a href="https://ollama.ai" target="_blank" style="color: white; text-decoration: underline;">
                                Install Ollama
                            </a> for AI features.
                        </p>
                    </div>
                </div>
            `;
        }
    } catch (error) {
        console.error('AI check failed:', error);
        statusDiv.className = 'ai-status unavailable';
        statusDiv.innerHTML = `
            <div style="text-align: center;">
                <span style="font-size: 1.5em;">❌</span>
                <p><strong>AI Service Check Failed</strong></p>
                <p style="opacity: 0.9;">Scanner will use fallback analysis</p>
            </div>
        `;
    }
}

/**
 * Format date/time string
 */
function formatDateTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    return date.toLocaleString();
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : '#667eea'};
        color: white;
        padding: 15px 25px;
        border-radius: 10px;
        box-shadow: 0 4px 16px rgba(0,0,0,0.2);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

/**
 * Validate URL format
 */
function isValidUrl(string) {
    try {
        new URL(string.startsWith('http') ? string : `https://${string}`);
        return true;
    } catch {
        return false;
    }
}

/**
 * Get selected scan types
 */
function getSelectedScanTypes() {
    const checkboxes = document.querySelectorAll('input[name="scanType"]:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

/**
 * Get selected AI model
 */
function getSelectedAIModel() {
    const radio = document.querySelector('input[name="aiModel"]:checked');
    return radio ? radio.value : 'llama3';
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
    
    @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    
    .spinner {
        display: inline-block;
        width: 20px;
        height: 20px;
        border: 3px solid rgba(255,255,255,0.3);
        border-top-color: white;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
    }
`;
document.head.appendChild(style);
