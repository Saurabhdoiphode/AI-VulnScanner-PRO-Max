"""
AI-VulnScanner PRO Max - Web Application
Flask-based web interface for vulnerability scanning
"""

from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS
import sys
import os
import logging
import threading
import uuid
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared_core.scanner import VulnerabilityScanner
from shared_core.report_generator import ReportGenerator
from shared_core.ai_engine import AIEngine

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global storage for scan sessions
scan_sessions = {}
scan_threads = {}

# Initialize report generator
report_generator = ReportGenerator()

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/scan', methods=['GET'])
def scan_page():
    """Scan configuration page"""
    return render_template('scan.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """
    Start a new vulnerability scan
    
    POST JSON:
    {
        "target": "https://example.com",
        "scan_types": ["web", "network", "osint", "ai"],
        "ai_model": "llama3"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'target' not in data:
            return jsonify({
                'success': False,
                'error': 'Target URL required'
            }), 400
        
        target = data['target']
        scan_types = data.get('scan_types', ['web', 'network', 'osint', 'ai'])
        ai_model = data.get('ai_model', 'llama3')
        ai_enabled = 'ai' in scan_types
        
        # Validate URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Initialize scan session
        scan_sessions[session_id] = {
            'status': 'initializing',
            'progress': 0,
            'message': 'Initializing scan...',
            'target': target,
            'start_time': datetime.now().isoformat(),
            'results': None,
            'error': None
        }
        
        # Create scanner with progress callback
        def progress_callback(message, percent):
            if session_id in scan_sessions:
                scan_sessions[session_id]['progress'] = percent
                scan_sessions[session_id]['message'] = message
                scan_sessions[session_id]['status'] = 'scanning'
        
        scanner = VulnerabilityScanner(
            ai_enabled=ai_enabled,
            ai_model=ai_model,
            progress_callback=progress_callback
        )
        
        # Start scan in background thread
        def run_scan():
            try:
                logger.info(f"Starting scan for {target} (session: {session_id})")
                
                results = scanner.full_scan(target, scan_types=scan_types)
                
                scan_sessions[session_id]['status'] = 'completed'
                scan_sessions[session_id]['progress'] = 100
                scan_sessions[session_id]['message'] = 'Scan complete!'
                scan_sessions[session_id]['results'] = results
                scan_sessions[session_id]['end_time'] = datetime.now().isoformat()
                
                logger.info(f"Scan completed for session {session_id}")
                
            except Exception as e:
                logger.error(f"Scan failed for session {session_id}: {e}")
                scan_sessions[session_id]['status'] = 'failed'
                scan_sessions[session_id]['error'] = str(e)
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        scan_threads[session_id] = thread
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/scan/status/<session_id>', methods=['GET'])
def scan_status(session_id):
    """
    Get scan status and progress
    
    Returns:
    {
        "status": "scanning|completed|failed",
        "progress": 0-100,
        "message": "Current status message",
        "target": "https://example.com",
        "start_time": "ISO timestamp"
    }
    """
    if session_id not in scan_sessions:
        return jsonify({
            'success': False,
            'error': 'Session not found'
        }), 404
    
    session_data = scan_sessions[session_id]
    
    return jsonify({
        'success': True,
        'status': session_data['status'],
        'progress': session_data['progress'],
        'message': session_data['message'],
        'target': session_data['target'],
        'start_time': session_data['start_time'],
        'error': session_data.get('error')
    })

@app.route('/api/scan/results/<session_id>', methods=['GET'])
def scan_results(session_id):
    """
    Get complete scan results
    
    Returns full scan results JSON
    """
    if session_id not in scan_sessions:
        return jsonify({
            'success': False,
            'error': 'Session not found'
        }), 404
    
    session_data = scan_sessions[session_id]
    
    if session_data['status'] != 'completed':
        return jsonify({
            'success': False,
            'error': 'Scan not completed yet'
        }), 400
    
    return jsonify({
        'success': True,
        'results': session_data['results']
    })

@app.route('/api/report/html/<session_id>', methods=['GET'])
def generate_html_report(session_id):
    """Generate and download HTML report"""
    if session_id not in scan_sessions:
        return jsonify({
            'success': False,
            'error': 'Session not found'
        }), 404
    
    session_data = scan_sessions[session_id]
    
    if session_data['status'] != 'completed':
        return jsonify({
            'success': False,
            'error': 'Scan not completed'
        }), 400
    
    try:
        filepath = report_generator.generate_html_report(session_data['results'])
        return send_file(
            filepath,
            as_attachment=True,
            download_name=f"report_{session_id}.html",
            mimetype='text/html'
        )
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/report/json/<session_id>', methods=['GET'])
def generate_json_report(session_id):
    """Generate and download JSON report"""
    if session_id not in scan_sessions:
        return jsonify({
            'success': False,
            'error': 'Session not found'
        }), 404
    
    session_data = scan_sessions[session_id]
    
    if session_data['status'] != 'completed':
        return jsonify({
            'success': False,
            'error': 'Scan not completed'
        }), 400
    
    try:
        filepath = report_generator.generate_json_report(session_data['results'])
        return send_file(
            filepath,
            as_attachment=True,
            download_name=f"report_{session_id}.json",
            mimetype='application/json'
        )
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/report/<session_id>', methods=['GET'])
def view_report(session_id: str):
    """View scan report in browser - generates and returns HTML report"""
    if session_id not in scan_sessions:
        return render_template('error.html', error='Session not found'), 404
    
    session_data = scan_sessions[session_id]
    
    if session_data['status'] != 'completed':
        return render_template('error.html', error='Scan not completed'), 400
    
    # Generate HTML report on the fly
    try:
        report_gen = ReportGenerator()
        html_report = report_gen._generate_html_content(session_data['results'])
        return html_report
    except Exception as e:
        return render_template('error.html', error=f'Report generation failed: {str(e)}'), 500

@app.route('/api/ai/check', methods=['GET'])
def check_ai():
    """Check if AI service is available"""
    try:
        ai_engine = AIEngine()
        available = ai_engine.check_availability()
        
        return jsonify({
            'success': True,
            'available': available,
            'models': ai_engine.models
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'available': False,
            'error': str(e)
        })

@app.route('/api/sessions', methods=['GET'])
def list_sessions():
    """List all scan sessions"""
    sessions = []
    
    for session_id, data in scan_sessions.items():
        sessions.append({
            'session_id': session_id,
            'target': data['target'],
            'status': data['status'],
            'progress': data['progress'],
            'start_time': data['start_time']
        })
    
    return jsonify({
        'success': True,
        'sessions': sessions
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'active_scans': len([s for s in scan_sessions.values() if s['status'] == 'scanning']),
        'total_sessions': len(scan_sessions)
    })

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return render_template('error.html', error='Internal server error'), 500

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║          AI-VulnScanner PRO Max - Web Application            ║
    ║                    Starting Server...                        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    print("Server will start on: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    print()
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )
