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
from datetime import datetime, timedelta
import sqlite3
import json
from urllib.parse import urlparse

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

# --- Simple caching layer with optional MongoDB and fallback to SQLite ---
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
DB_PATH = os.path.join(DB_DIR, 'scans.db')
MONGODB_URI = os.environ.get('MONGODB_URI')

# Optional Mongo client (if env var provided)
mongo_client = None
mongo_collection = None
try:
    if MONGODB_URI:
        from pymongo import MongoClient, ASCENDING
        from pymongo.errors import PyMongoError
        mongo_client = MongoClient(MONGODB_URI)
        db = mongo_client.get_default_database() if mongo_client.get_default_database() else mongo_client['vulnscanner']
        mongo_collection = db['scans']
        # Ensure TTL index on created_at (10 days = 864000 seconds)
        mongo_collection.create_index([('created_at', ASCENDING)], expireAfterSeconds=864000)
        logger.info("MongoDB caching enabled (TTL 10 days)")
except Exception as me:
    logger.warning(f"MongoDB init failed, falling back to SQLite: {me}")
    mongo_client = None
    mongo_collection = None

def _ensure_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                normalized_target TEXT NOT NULL,
                scan_types TEXT NOT NULL,
                ai_model TEXT,
                results_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

def _normalize_target(url: str) -> str:
    try:
        parsed = urlparse(url)
        return (parsed.hostname or url).lower()
    except Exception:
        return url.lower()

def _scan_types_key(scan_types):
    return ','.join(sorted(scan_types or []))

def _cleanup_expired():
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        from datetime import timezone
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("DELETE FROM scans WHERE expires_at < ?", (now,))
        conn.commit()
    finally:
        conn.close()

def _get_cached_result(target: str, scan_types, ai_model: str):
    # Prefer MongoDB if configured and available
    if mongo_collection is not None:
        try:
            from datetime import timezone
            norm = _normalize_target(target)
            key = _scan_types_key(scan_types)
            doc = mongo_collection.find_one(
                {
                    'normalized_target': norm,
                    'scan_types': key,
                    'ai_model': ai_model or ''
                },
                sort=[('created_at', -1)]
            )
            if doc and doc.get('results'):
                return doc['results']
        except Exception as e:
            logger.warning(f"Mongo cache read failed, falling back to SQLite: {e}")

    # SQLite fallback
    _ensure_db()
    _cleanup_expired()
    norm = _normalize_target(target)
    key = _scan_types_key(scan_types)
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT results_json FROM scans
            WHERE normalized_target = ? AND scan_types = ? AND IFNULL(ai_model,'') = IFNULL(?, '')
            ORDER BY datetime(created_at) DESC
            LIMIT 1
            """,
            (norm, key, ai_model)
        )
        row = cur.fetchone()
        if row and row[0]:
            try:
                return json.loads(row[0])
            except Exception:
                return None
        return None
    finally:
        conn.close()

def _save_scan_result(target: str, scan_types, ai_model: str, results: dict):
    # Prefer MongoDB if configured and available
    if mongo_collection is not None:
        try:
            from datetime import timezone
            now = datetime.now(timezone.utc)
            doc = {
                'target': target,
                'normalized_target': _normalize_target(target),
                'scan_types': _scan_types_key(scan_types),
                'ai_model': ai_model or '',
                'results': results,
                'created_at': now,
            }
            mongo_collection.insert_one(doc)
            return
        except Exception as e:
            logger.warning(f"Mongo cache write failed, falling back to SQLite: {e}")

    # SQLite fallback
    _ensure_db()
    from datetime import timezone
    norm = _normalize_target(target)
    key = _scan_types_key(scan_types)
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=10)
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO scans (target, normalized_target, scan_types, ai_model, results_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                norm,
                key,
                ai_model,
                json.dumps(results),
                created_at.isoformat(),
                expires_at.isoformat()
            )
        )
        conn.commit()
    finally:
        conn.close()

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
        
        # Check cache first (10-day TTL)
        cached = _get_cached_result(target, scan_types, ai_model if ai_enabled else '')
        if cached:
            session_id = str(uuid.uuid4())
            scan_sessions[session_id] = {
                'status': 'completed',
                'progress': 100,
                'message': 'Loaded cached results (valid < 10 days)',
                'target': target,
                'start_time': datetime.now().isoformat(),
                'results': cached,
                'end_time': datetime.now().isoformat(),
                'error': None
            }
            return jsonify({
                'success': True,
                'session_id': session_id,
                'cached': True,
                'message': 'Using cached results'
            })

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
                # Save to cache
                try:
                    _save_scan_result(target, scan_types, ai_model if ai_enabled else '', results)
                except Exception as se:
                    logger.warning(f"Failed to save cached results: {se}")
                
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
        from flask import Response
        # Generate HTML content directly without writing to disk
        html_content = report_generator._generate_html_content(session_data['results'])
        
        return Response(
            html_content,
            mimetype='text/html',
            headers={
                'Content-Disposition': f'attachment; filename="report_{session_id}.html"'
            }
        )
    except Exception as e:
        logger.error(f"HTML report generation failed: {e}")
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
        from flask import Response
        import json as json_lib
        # Generate JSON content directly without writing to disk
        json_content = json_lib.dumps(session_data['results'], indent=2)
        
        return Response(
            json_content,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename="report_{session_id}.json"'
            }
        )
    except Exception as e:
        logger.error(f"JSON report generation failed: {e}")
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
    
    # Get port from environment variable (for deployment) or use 5000
    import os
    port = int(os.environ.get('PORT', 5000))
    
    print(f"Server will start on: http://localhost:{port}")
    print("Press Ctrl+C to stop the server")
    print()
    
    # Prepare DB cache on startup
    try:
        if mongo_collection is None:
            _ensure_db()
            _cleanup_expired()
    except Exception as e:
        logger.warning(f"Cache initialization warning: {e}")

    app.run(
        host='0.0.0.0',
        port=port,
        debug=os.environ.get('FLASK_ENV') != 'production',
        threaded=True
    )
