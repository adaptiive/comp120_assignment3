from flask import Flask, render_template, jsonify, request, session
import speedtest
import threading
import time
import json
import sqlite3
from datetime import datetime, timedelta
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'wifi_speed_test_secret_key_2024'

# Global variable to store the latest speed test results
latest_results = {
    'download': 0,
    'upload': 0,
    'ping': 0,
    'timestamp': None,
    'testing': False,
    'status': 'Ready'
}

# Historical data storage (in production, use a database)
test_history = []

# Database file
DB_PATH = os.path.join(os.path.dirname(__file__), 'speedtest.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # Create tests table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS tests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        download REAL,
        upload REAL,
        ping REAL,
        server TEXT,
        user_role TEXT,
        username TEXT
    )
    ''')
    # Create users table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        display_name TEXT
    )
    ''')
    # Create reports table for storing generated ISP reports
    cur.execute('''
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT UNIQUE,
        generated_at TEXT,
        creator TEXT,
        customer TEXT,
        summary TEXT,
        payload TEXT
    )
    ''')
    conn.commit()
    conn.close()

def seed_demo_users():
    conn = get_db_connection()
    cur = conn.cursor()
    demo = [
        ('itadmin', 'admin123', 'it_admin', 'IT Admin'),
        ('ispagent', 'isp123', 'isp_support', 'ISP Agent')
    ]
    for username, password, role, display in demo:
        # If user doesn't exist, insert with hashed password. If exists but password is plain, update it.
        cur.execute('SELECT password FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        pw_hash = generate_password_hash(password)
        if not row:
            try:
                cur.execute('INSERT INTO users (username, password, role, display_name) VALUES (?, ?, ?, ?)',
                            (username, pw_hash, role, display))
            except sqlite3.IntegrityError:
                pass
        else:
            existing_pw = row['password']
            # crude check: if existing password doesn't look like a werkzeug hash, update it
            if not (existing_pw.startswith('pbkdf2:') or existing_pw.startswith('sha256$') or existing_pw.count('$') >= 2):
                cur.execute('UPDATE users SET password = ? WHERE username = ?', (pw_hash, username))
    conn.commit()
    conn.close()

# Initialize DB on import
init_db()
seed_demo_users()

# User roles configuration
USER_ROLES = {
    'home_user': {
        'name': 'Home User',
        'description': 'Simple speed testing for personal use',
        'features': ['basic_test', 'simple_results']
    },
    'it_admin': {
        'name': 'IT Administrator', 
        'description': 'Network management and monitoring',
        'features': ['basic_test', 'detailed_results', 'history', 'diagnostics']
    },
    'isp_support': {
        'name': 'ISP Customer Support',
        'description': 'Customer support and troubleshooting',
        'features': ['basic_test', 'detailed_results', 'diagnostics', 'report_sharing']
    }
}

def run_speed_test(user_role='home_user'):
    """Run speed test in background thread.

    Accepts user_role to avoid accessing Flask session from a background thread.
    """
    global latest_results, test_history
    
    try:
        latest_results['testing'] = True
        latest_results['status'] = 'Finding best server...'
        
        # Configure speedtest with timeout and faster settings
        st = speedtest.Speedtest(timeout=10)
        
        # Get best server (faster server selection)
        st.get_best_server()
        
        # Test download speed (with smaller test size for faster results)
        latest_results['status'] = 'Testing download speed...'
        download_speed = st.download(threads=1) / 1_000_000  # Single thread, convert to Mbps
        latest_results['download'] = round(download_speed, 2)
        
        # Test upload speed (with smaller test size for faster results)
        latest_results['status'] = 'Testing upload speed...'
        upload_speed = st.upload(threads=1) / 1_000_000  # Single thread, convert to Mbps
        latest_results['upload'] = round(upload_speed, 2)
        
        # Get ping
        latest_results['status'] = 'Measuring ping...'
        latest_results['ping'] = round(st.results.ping, 2)
        
        # Update timestamp
        latest_results['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
        latest_results['status'] = 'Complete'
        
        # Store in history (write to DB)
        server_name = st.results.server['name'] if getattr(st.results, 'server', None) else 'Unknown'
        # append to in-memory cache as well
        test_history.append({
            'timestamp': latest_results['timestamp'],
            'download': latest_results['download'],
            'upload': latest_results['upload'],
            'ping': latest_results['ping'],
            'server': server_name,
            'user_role': user_role
        })
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('INSERT INTO tests (timestamp, download, upload, ping, server, user_role, username) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        (latest_results['timestamp'], latest_results['download'], latest_results['upload'], latest_results['ping'], server_name, user_role, session.get('username') if session else None))
            conn.commit()
            conn.close()
        except Exception as e:
            print('Failed to write test to DB:', e)
        
        # Keep only last 50 tests
        if len(test_history) > 50:
            test_history.pop(0)
        
    except Exception as e:
        print(f"Error during speed test: {e}")
        latest_results['download'] = 0
        latest_results['upload'] = 0
        latest_results['ping'] = 0
        latest_results['status'] = f'Error: {str(e)}'
    
    finally:
        latest_results['testing'] = False

@app.route('/')
def index():
    """Main page"""
    user_role = session.get('user_role', None)
    return render_template('index.html', user_role=user_role, roles=USER_ROLES)

@app.route('/set-role', methods=['POST'])
def set_role():
    """Set user role"""
    # Allow selecting a role before login (pre-login role picker).
    # Once authenticated, the user's role is fixed by their login and cannot be changed.
    role = request.json.get('role')
    if role not in USER_ROLES:
        return jsonify({'status': 'error', 'message': 'Invalid role'}), 400

    if session.get('authenticated'):
        # Prevent changing role after login
        current = session.get('user_role')
        if current == role:
            return jsonify({'status': 'success', 'role': role})
        return jsonify({'status': 'error', 'message': 'Cannot change role after login'}), 403

    # Not authenticated: allow choosing a role (for UI purposes)
    session['user_role'] = role
    return jsonify({'status': 'success', 'role': role})

@app.route('/get-role')
def get_role():
    """Get current user role"""
    role = session.get('user_role', None)
    return jsonify({
        'role': role,
        'config': USER_ROLES.get(role) if role else None,
        'authenticated': session.get('authenticated', False),
        'username': session.get('username')
    })


@app.route('/login', methods=['POST'])
def login():
    """Simple login endpoint. For 'home_user' (customer) no password is required.

    For 'it_admin' and 'isp_support' a username/password is required and checked
    against the demo USERS dict. This is a prototype; don't use in production.
    """
    data = request.json or {}
    role = data.get('role')
    username = (data.get('username') or 'guest').strip()
    # normalize username for lookup
    username_lookup = username.lower()
    password = data.get('password', '')

    if role not in USER_ROLES:
        return jsonify({'status': 'error', 'message': 'Invalid role'}), 400

    # Home users (customers) can login without password
    if role == 'home_user':
        session['authenticated'] = True
        session['user_role'] = 'home_user'
        session['username'] = username
        return jsonify({'status': 'success', 'role': 'home_user', 'username': username})

    # For admin/isp require matching user from DB with valid password
    conn = get_db_connection()
    cur = conn.cursor()
    # lookup case-insensitively by lower(username)
    cur.execute('SELECT username, password, role FROM users WHERE LOWER(username) = LOWER(?)', (username_lookup,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({'status': 'error', 'message': 'User not found'}), 401
    if row['role'] != role:
        return jsonify({'status': 'error', 'message': 'Selected role does not match user account'}), 401

    stored_pw = row['password']
    if not password:
        return jsonify({'status': 'error', 'message': 'Password required for this role'}), 401
    if not check_password_hash(stored_pw, password):
        return jsonify({'status': 'error', 'message': 'Invalid password'}), 401

    session['authenticated'] = True
    session['user_role'] = role
    session['username'] = row['username']
    return jsonify({'status': 'success', 'role': role, 'username': row['username']})


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'success'})

@app.route('/start-test')
def start_test():
    """Start speed test"""
    if not latest_results['testing']:
        role = session.get('user_role', 'home_user')
        thread = threading.Thread(target=run_speed_test, args=(role,))
        thread.daemon = True
        thread.start()
        return jsonify({'status': 'started'})
    else:
        return jsonify({'status': 'already_running'})

@app.route('/results')
def get_results():
    """Get current results"""
    user_role = session.get('user_role', 'home_user')
    result = latest_results.copy()
    
    # Add role-specific data
    if user_role == 'it_admin' or user_role == 'isp_support':
        result['detailed'] = True
        result['server_info'] = 'Available after test'
    
    return jsonify(result)

@app.route('/history')
def get_history():
    """Get test history (IT Admin and ISP Support only)"""
    user_role = session.get('user_role', 'home_user')
    
    if user_role not in ['it_admin', 'isp_support']:
        return jsonify({'error': 'Access denied'}), 403

    # Filter history by time range if requested
    days = request.args.get('days', 7, type=int)
    cutoff_date = datetime.now() - timedelta(days=days)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT timestamp, download, upload, ping, server, user_role, username FROM tests WHERE timestamp >= ? ORDER BY id DESC', (cutoff_date.strftime('%Y-%m-%d %H:%M:%S'),))
    rows = cur.fetchall()
    conn.close()

    history = [dict(r) for r in rows]
    return jsonify({'history': history, 'total_tests': len(history)})

@app.route('/diagnostics')
def get_diagnostics():
    """Get network diagnostics (IT Admin and ISP Support only)"""
    user_role = session.get('user_role', 'home_user')
    
    if user_role not in ['it_admin', 'isp_support']:
        return jsonify({'error': 'Access denied'}), 403
    
    # Basic network diagnostics
    # Compute diagnostics from DB
    conn = get_db_connection()
    cur = conn.cursor()
    # tests today
    today_prefix = time.strftime('%Y-%m-%d')
    cur.execute('SELECT COUNT(*) as cnt FROM tests WHERE timestamp LIKE ?', (today_prefix + '%',))
    tests_today = cur.fetchone()['cnt']
    # last 10 tests averages
    cur.execute('SELECT download, upload, ping FROM tests ORDER BY id DESC LIMIT 10')
    rows = cur.fetchall()
    conn.close()

    if rows:
        downloads = [r['download'] for r in rows]
        uploads = [r['upload'] for r in rows]
        pings = [r['ping'] for r in rows]
        avg_download = round(sum(downloads) / len(downloads), 2)
        avg_upload = round(sum(uploads) / len(uploads), 2)
        avg_ping = round(sum(pings) / len(pings), 2)
    else:
        avg_download = avg_upload = avg_ping = 0

    diagnostics = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'tests_today': tests_today,
        'avg_download': avg_download,
        'avg_upload': avg_upload,
        'avg_ping': avg_ping,
    }
    
    return jsonify(diagnostics)

@app.route('/generate-report')
def generate_report():
    """Generate a shareable report (ISP Support only)"""
    user_role = session.get('user_role', 'home_user')
    
    if user_role != 'isp_support':
        return jsonify({'error': 'Access denied'}), 403
    
    # Allow ISP agent to optionally specify a customer username to include historical context
    customer = request.args.get('customer') or session.get('username')

    # Ensure we have at least a latest test to report on
    if not latest_results['timestamp']:
        return jsonify({'error': 'No test results available'})

    # Gather related historical tests (for the customer if provided, otherwise recent global)
    conn = get_db_connection()
    cur = conn.cursor()
    if customer:
        cur.execute('SELECT timestamp, download, upload, ping, server, user_role, username FROM tests WHERE username = ? ORDER BY id DESC LIMIT 10', (customer,))
    else:
        cur.execute('SELECT timestamp, download, upload, ping, server, user_role, username FROM tests ORDER BY id DESC LIMIT 10')
    rows = cur.fetchall()

    tests = [dict(r) for r in rows]

    # Compute simple diagnostics for the included tests
    if tests:
        downloads = [t['download'] for t in tests]
        uploads = [t['upload'] for t in tests]
        pings = [t['ping'] for t in tests]
        avg_download = round(sum(downloads) / len(downloads), 2)
        avg_upload = round(sum(uploads) / len(uploads), 2)
        avg_ping = round(sum(pings) / len(pings), 2)
    else:
        avg_download = latest_results['download']
        avg_upload = latest_results['upload']
        avg_ping = latest_results['ping']

    # Basic recommendations
    suggestions = []
    if avg_download < 10:
        suggestions.append('Low download speeds — suggest checking client WiFi signal, router location, and ISP plan limits.')
    elif avg_download < 25:
        suggestions.append('Moderate download speeds — try rebooting network devices and testing during off-peak hours.')
    else:
        suggestions.append('Download speeds are within expected range.')

    if avg_ping > 100:
        suggestions.append('High latency observed — check for packet loss, heavy local traffic, or routing issues.')

    report = {
        'report_id': f"REPORT_{int(time.time())}",
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'latest_test': {
            'download_mbps': latest_results['download'],
            'upload_mbps': latest_results['upload'],
            'ping_ms': latest_results['ping'],
            'test_timestamp': latest_results['timestamp'],
            'server': latest_results.get('server_info', 'Unknown')
        },
        'history': tests,
        'averages': {
            'avg_download': avg_download,
            'avg_upload': avg_upload,
            'avg_ping': avg_ping
        },
        'suggestions': suggestions,
        'summary': f"Customer speed test summary: {latest_results['download']} Mbps down, {latest_results['upload']} Mbps up, {latest_results['ping']} ms ping"
    }

    conn.close()

    # Also include a minimal HTML snippet to present the report in the UI
    report_html = (
        f"<div style='font-family:Arial,sans-serif;color:#222'><h2>{report['report_id']}</h2>"
        f"<p><strong>Customer:</strong> {report['customer'] or 'N/A'}</p>"
        f"<p><strong>Generated:</strong> {report['generated_at']}</p>"
        f"<h3>Latest Test</h3><ul><li>Download: {report['latest_test']['download_mbps']} Mbps</li>"
        f"<li>Upload: {report['latest_test']['upload_mbps']} Mbps</li><li>Ping: {report['latest_test']['ping_ms']} ms</li>"
        f"<li>Server: {report['latest_test']['server']}</li></ul><h3>Averages (history)</h3><ul>"
        f"<li>Avg Download: {report['averages']['avg_download']} Mbps</li>"
        f"<li>Avg Upload: {report['averages']['avg_upload']} Mbps</li>"
        f"<li>Avg Ping: {report['averages']['avg_ping']} ms</li></ul><h3>Suggestions</h3><ul>"
        + ''.join(f"<li>{s}</li>" for s in suggestions)
        + "</ul></div>"
    )

    report['report_html'] = report_html

    # Persist the generated report for IT Admin access
    try:
        conn2 = get_db_connection()
        cur2 = conn2.cursor()
        cur2.execute('INSERT OR REPLACE INTO reports (report_id, generated_at, creator, customer, summary, payload) VALUES (?, ?, ?, ?, ?, ?)',
                     (report['report_id'], report['generated_at'], session.get('username'), report['customer'], report['summary'], json.dumps(report)))
        conn2.commit()
        conn2.close()
    except Exception as e:
        # Log but don't fail the report generation for UI
        print('Failed to persist report:', e)

    return jsonify(report)

@app.route('/clear-history', methods=['POST'])
def clear_history():
    """Clear test history (IT Admin only)"""
    user_role = session.get('user_role', 'home_user')
    
    if user_role != 'it_admin':
        return jsonify({'error': 'Access denied'}), 403
    
    # Clear DB history
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM tests')
    conn.commit()
    conn.close()
    # Clear memory cache too
    test_history.clear()
    return jsonify({'status': 'success', 'message': 'History cleared'})


@app.route('/reports')
def list_reports():
    """List stored reports (IT Admin only)"""
    user_role = session.get('user_role', 'home_user')
    if user_role != 'it_admin':
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT report_id, generated_at, creator, customer, summary FROM reports ORDER BY id DESC')
    rows = cur.fetchall()
    conn.close()

    reports = [dict(r) for r in rows]
    return jsonify({'reports': reports})


@app.route('/reports/<report_id>')
def get_report(report_id):
    """Retrieve a full report payload by report_id (IT Admin only)"""
    user_role = session.get('user_role', 'home_user')
    if user_role != 'it_admin':
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT payload FROM reports WHERE report_id = ?', (report_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Report not found'}), 404

    try:
        payload = json.loads(row['payload'])
    except Exception:
        return jsonify({'error': 'Failed to parse report payload'}), 500

    return jsonify(payload)

@app.route('/export-data')
def export_data():
    """Export test data (IT Admin and ISP Support only)"""
    user_role = session.get('user_role', 'home_user')
    
    if user_role not in ['it_admin', 'isp_support']:
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT timestamp, download, upload, ping, server, user_role, username FROM tests ORDER BY id DESC')
    rows = cur.fetchall()
    conn.close()

    export_data = {
        'export_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'user_role': user_role,
        'test_history': [dict(r) for r in rows],
        'latest_results': latest_results,
        'total_tests': len(rows)
    }
    
    return jsonify(export_data)

@app.route('/network-status')
def network_status():
    """Get network status overview (IT Admin and ISP Support only)"""
    user_role = session.get('user_role', 'home_user')
    
    if user_role not in ['it_admin', 'isp_support']:
        return jsonify({'error': 'Access denied'}), 403
    
    # Calculate network health indicators
    # derive from DB recent tests
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT download, upload, ping FROM tests ORDER BY id DESC LIMIT 5')
    rows = cur.fetchall()
    conn.close()

    if rows:
        avg_download = sum([r['download'] for r in rows]) / len(rows)
        avg_upload = sum([r['upload'] for r in rows]) / len(rows)
        avg_ping = sum([r['ping'] for r in rows]) / len(rows)
        # Simple health scoring
        download_health = 'Good' if avg_download > 25 else 'Fair' if avg_download > 10 else 'Poor'
        upload_health = 'Good' if avg_upload > 5 else 'Fair' if avg_upload > 2 else 'Poor'
        ping_health = 'Good' if avg_ping < 50 else 'Fair' if avg_ping < 100 else 'Poor'
    else:
        download_health = upload_health = ping_health = 'No Data'
        avg_download = avg_upload = avg_ping = 0
    
    status = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'overall_health': 'Good' if all(h == 'Good' for h in [download_health, upload_health, ping_health]) else 'Fair',
        'download_health': download_health,
        'upload_health': upload_health,
        'ping_health': ping_health,
        'recent_avg_download': round(avg_download, 2),
        'recent_avg_upload': round(avg_upload, 2),
        'recent_avg_ping': round(avg_ping, 2),
        'total_tests_count': len(test_history)
    }
    
    return jsonify(status)

if __name__ == '__main__':
    # Allow controlling debug/reloader via environment variables so the app
    # can be started safely without VS Code's debugger or the Werkzeug reloader
    import os

    # FLASK_DEBUG=1 or 'true' enables debug mode; otherwise run in non-debug mode
    debug_env = os.environ.get('FLASK_DEBUG', '0').lower()
    debug = debug_env in ('1', 'true', 'yes')

    # By default avoid the automatic reloader when running outside of debugger
    # as some Windows environments (and some editor-run scenarios) can pass
    # invalid socket fds to the reloader child which causes OSError WinError 10038.
    use_reloader_env = os.environ.get('FLASK_USE_RELOADER', None)
    if use_reloader_env is not None:
        use_reloader = use_reloader_env.lower() in ('1', 'true', 'yes')
    else:
        # default: only enable reloader when explicitly in debug mode and
        # when the user hasn't disabled it via env var
        use_reloader = False if not debug else True

    try:
        app.run(debug=debug, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), use_reloader=use_reloader)
    except OSError as e:
        # Known Windows issue: reloader child may receive an invalid fd; retry
        # without the reloader which avoids socket.fromfd usage.
        print(f"OSError when starting server: {e}; retrying with use_reloader=False")
        app.run(debug=debug, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), use_reloader=False)