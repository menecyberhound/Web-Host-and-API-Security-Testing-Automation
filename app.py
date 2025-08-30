"""
Security Scanner Web Application

This Flask application provides a web interface for running security scans against web applications
using OWASP ZAP. It includes features for scheduling scans, viewing results, and managing security
findings through a user-friendly dashboard.

The application integrates with ZAP for scanning, uses SQLite for data storage, and provides
both synchronous and asynchronous scanning capabilities with real-time progress tracking.

Features:
    - Web-based dashboard for security scan management
    - Real-time scan progress monitoring
    - Scheduled scan automation
    - Risk-based vulnerability prioritization
    - Export and import of scan results
    - Historical scan data tracking

Dependencies:
    - Flask: Web framework
    - SQLite: Database backend
    - ZAP: Security scanning engine
    - APScheduler: Scan scheduling
"""

import sqlite3
from flask import Flask, render_template, jsonify, request, send_file
from datetime import datetime, timedelta
import os
import uuid
import threading
import time
import logging
from werkzeug.utils import secure_filename
import csv
import io
from zap_scanner import ZAPScanner
from risk_engine import RiskEngine
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', str(uuid.uuid4()))
DB_PATH = os.environ.get('DB_PATH', 'scan_results.db')

# Add functions to Jinja2 environment
app.jinja_env.globals.update(zip=zip, range=range, len=len)

# Dictionary to store active scans and their status
active_scans = {}

# Initialize the scheduler
scheduler = BackgroundScheduler()
scheduler.start()

def get_db_connection():
    """
    Create and return a connection to the SQLite database.

    The connection is configured to return Row objects for better dictionary-like access
    to query results.

    Returns:
        sqlite3.Connection: A connection to the SQLite database

    Raises:
        Exception: If unable to establish database connection
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise

def init_db():
    """
    Initialize the database schema if it doesn't exist.

    Creates the following tables if they don't exist:
    - alerts: Stores individual security findings
    - scans: Stores scan metadata and summary information
    - scheduled_scans: Stores scan scheduling information

    Each table is created with appropriate columns and constraints for maintaining
    data integrity and relationships between tables.
    """
    try:
        if not os.path.exists(DB_PATH):
            conn = get_db_connection()
            conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                alert_name TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                url TEXT NOT NULL,
                cwe_id TEXT,
                description TEXT,
                is_critical_endpoint INTEGER,
                confidence TEXT,
                scan_date TEXT,
                scan_id INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
            ''')
            conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                total_alerts INTEGER,
                high_risk INTEGER,
                medium_risk INTEGER,
                low_risk INTEGER,
                info_risk INTEGER,
                status TEXT DEFAULT 'Completed',
                duration INTEGER DEFAULT 0,
                scan_type TEXT DEFAULT 'Full',
                progress INTEGER DEFAULT 0
            )
            ''')
            conn.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id INTEGER PRIMARY KEY,
                target_url TEXT NOT NULL,
                schedule_type TEXT NOT NULL,
                schedule_time TEXT NOT NULL,
                schedule_day TEXT,
                next_scan_date TEXT,
                last_scan_date TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                is_active INTEGER DEFAULT 1,
                description TEXT
            )
            ''')
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

@app.route('/')
def index():
    """
    Render the main dashboard page.

    Displays:
    - Risk summary chart
    - Recent scan history
    - Overall security metrics

    Returns:
        str: Rendered HTML template with dashboard data
    """
    conn = get_db_connection()
    # Get risk summary
    summary = conn.execute('SELECT risk_level, COUNT(*) AS count FROM alerts GROUP BY risk_level').fetchall()

    # Create simple chart data - avoid any complex Jinja operations
    chart_data = {
        'labels': [],
        'data': [],
        'colors': ['#dc3545', '#ffc107', '#17a2b8', '#6c757d']  # Red, Yellow, Blue, Gray
    }

    # Populate chart data if we have results
    if summary:
        chart_data['labels'] = [row['risk_level'] for row in summary]
        chart_data['data'] = [row['count'] for row in summary]
    else:
        # Default empty data
        chart_data['labels'] = ['High', 'Medium', 'Low', 'Informational']
        chart_data['data'] = [0, 0, 0, 0]

    # Get recent scans
    recent_scans = conn.execute('SELECT * FROM scans ORDER BY scan_date DESC LIMIT 5').fetchall()
    recent_scans = [dict(row) for row in recent_scans] if recent_scans else []

    conn.close()

    # Use a simple template approach - render home.html with guaranteed data
    return render_template('home.html', chart_data=chart_data, recent_scans=recent_scans)

@app.route('/api/alerts')
def get_alerts():
    """
    API endpoint to retrieve all security alerts.

    Returns:
        Response: JSON array of all security alerts in the database
    """
    conn = get_db_connection()
    alerts = conn.execute('SELECT * FROM alerts').fetchall()
    conn.close()
    alerts_list = [dict(row) for row in alerts]
    return jsonify(alerts_list)

@app.route('/api/scan/<int:scan_id>')
def get_scan_details(scan_id):
    """
    API endpoint to get detailed information about a specific scan.

    Args:
        scan_id (int): The ID of the scan to retrieve

    Returns:
        Response: JSON object containing scan details and associated alerts

    Raises:
        404: If the specified scan is not found
    """
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return jsonify({"error": "Scan not found"}), 404

    alerts = conn.execute('SELECT * FROM alerts WHERE scan_date = ?', (scan['scan_date'],)).fetchall()
    conn.close()

    return jsonify({
        "scan": dict(scan),
        "alerts": [dict(alert) for alert in alerts]
    })

@app.route('/dashboard')
def dashboard():
    """Renders a simplified dashboard with a table of alerts."""
    return render_template('dashboard.html')

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    """
    Render the detailed view page for a specific scan.

    Args:
        scan_id (int): The ID of the scan to display

    Returns:
        str: Rendered HTML template with scan details

    Raises:
        404: If the specified scan is not found
    """
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return "Scan not found", 404

    conn.close()
    return render_template('scan_details.html', scan=dict(scan))

@app.route('/api/store_scan_results', methods=['POST'])
def store_scan_results():
    """
    API endpoint to store scan results from ZAP scanner.

    Expects a JSON payload containing:
    - target_url: URL that was scanned
    - alerts: Array of security findings

    Returns:
        Response: JSON confirmation of storage success with timestamp

    Raises:
        400: If the request is not valid JSON
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.json
    scan_date = datetime.now().isoformat()

    conn = get_db_connection()

    # Insert scan record
    high = sum(1 for alert in data['alerts'] if alert['risk_level'] == 'High')
    medium = sum(1 for alert in data['alerts'] if alert['risk_level'] == 'Medium')
    low = sum(1 for alert in data['alerts'] if alert['risk_level'] == 'Low')
    info = sum(1 for alert in data['alerts'] if alert['risk_level'] == 'Informational')

    conn.execute('''
    INSERT INTO scans (target_url, scan_date, total_alerts, high_risk, medium_risk, low_risk, info_risk)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (data['target_url'], scan_date, len(data['alerts']), high, medium, low, info))

    # Insert alert records
    for alert in data['alerts']:
        conn.execute('''
        INSERT INTO alerts (alert_name, risk_level, url, cwe_id, description, is_critical_endpoint, confidence, scan_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert['alert_name'],
            alert['risk_level'],
            alert['url'],
            alert.get('cwe_id', 'N/A'),
            alert.get('description', 'N/A'),
            1 if alert.get('is_critical_endpoint', False) else 0,
            alert.get('confidence', 'N/A'),
            scan_date
        ))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "scan_date": scan_date})

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """
    Start a new security scan.

    Expects form data containing:
    - target_url: The URL to scan

    Returns:
        Response: JSON object with scan_id for tracking progress

    Raises:
        400: If target_url is not provided
    """
    target_url = request.form.get('target_url')
    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    # Generate a unique ID for this scan
    scan_id = str(uuid.uuid4())

    # Initialize scan status in the active_scans dictionary
    active_scans[scan_id] = {
        'target_url': target_url,
        'status': 'Initializing',
        'progress': 0,
        'completed': False,
        'scan_db_id': None
    }

    # Start the scan in a background thread
    scan_thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target_url),
        daemon=True
    )
    scan_thread.start()

    return jsonify({"scan_id": scan_id})

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """
    Check the status of a running scan.

    Args:
        scan_id (str): UUID of the scan to check

    Returns:
        Response: JSON object containing scan status information including:
        - target_url: URL being scanned
        - status: Current status message
        - progress: Percentage complete (0-100)
        - completed: Boolean indicating if scan is finished
        - scan_db_id: Database ID of the scan record
    """
    # First check if scan is in active scans
    if scan_id in active_scans:
        scan_info = active_scans[scan_id]
        # Check if there's a cached progress in the scan info
        current_progress = scan_info.get('progress', 0)

        # Get the latest progress from the database for ongoing scans
        if not scan_info.get('completed', False):
            try:
                conn = get_db_connection()
                # Look for recent progress updates in the logs
                scan = conn.execute('''
                    SELECT status, progress FROM scans 
                    WHERE id = ? AND status != 'Completed'
                ''', (scan_info.get('scan_db_id'),)).fetchone()

                if scan:
                    # Update the cached progress if it's higher
                    db_progress = scan['progress'] if scan['progress'] is not None else current_progress
                    if db_progress > current_progress:
                        active_scans[scan_id]['progress'] = db_progress
                        current_progress = db_progress

                conn.close()
            except Exception as e:
                logger.error(f"Error checking database progress: {e}")

        return jsonify({
            'target_url': scan_info['target_url'],
            'status': scan_info['status'],
            'progress': current_progress,
            'completed': scan_info['completed'],
            'scan_db_id': scan_info.get('scan_db_id')
        })

    # If not in active scans, check if it's a completed scan in database
    try:
        conn = get_db_connection()
        # Look for recent scans that might match this scan ID pattern
        recent_scan = conn.execute('''
            SELECT * FROM scans 
            WHERE datetime(scan_date) >= datetime('now', '-1 hour')
            ORDER BY scan_date DESC 
            LIMIT 1
        ''').fetchone()
        conn.close()

        if recent_scan:
            # Return completed status with scan database ID
            return jsonify({
                'target_url': recent_scan['target_url'],
                'status': 'Completed',
                'progress': 100,
                'completed': True,
                'scan_db_id': recent_scan['id']
            })
        else:
            # Scan not found anywhere - it may have expired or failed
            return jsonify({
                'status': 'Scan not found or expired',
                'progress': 0,
                'completed': True,
                'error': 'Scan session expired or was not found'
            }), 404

    except Exception as e:
        logger.error(f"Error checking scan status for {scan_id}: {e}")
        return jsonify({"error": "Error checking scan status"}), 500

def get_local_datetime():
    """Get current datetime in local timezone"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def run_scan(scan_id, target_url, scheduled_scan_id=None):
    """
    Run a ZAP scan in a background thread.

    Args:
        scan_id (str): Unique identifier for the scan
        target_url (str): The URL to be scanned
        scheduled_scan_id (int, optional): ID of the associated scheduled scan, if any
    """
    try:
        logger.info(f"Starting scan {scan_id} for {target_url}")

        # Create initial scan record in database with local time
        conn = get_db_connection()
        conn.execute('''
        INSERT INTO scans (target_url, scan_date, status, progress)
        VALUES (?, ?, ?, ?)
        ''', (target_url, get_local_datetime(), 'Initializing', 0))
        conn.commit()

        # Get the scan database ID
        scan_db_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()

        # Update active scans dictionary
        active_scans[scan_id] = {
            'target_url': target_url,
            'status': 'Starting ZAP container',
            'progress': 5,
            'completed': False,
            'scan_db_id': scan_db_id
        }

        # Update database with status
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Starting ZAP container', 5, scan_db_id))
        conn.commit()
        conn.close()

        logger.info(f"Scan {scan_id}: Starting ZAP container")

        # Use the fixed API key that matches the ZAP container configuration
        api_key = "zap-api-key-12345"
        logger.info(f"Scan {scan_id}: Using fixed API key")

        # Initialize the scanner
        scanner = ZAPScanner(target_url=target_url, api_key=api_key)
        logger.info(f"Scan {scan_id}: ZAP Scanner initialized")

        # Check ZAP readiness
        scanner.start_zap_container()
        logger.info(f"Scan {scan_id}: ZAP container started successfully")

        # Update status for passive scan
        active_scans[scan_id]['status'] = 'Running passive scan (spider)'
        active_scans[scan_id]['progress'] = 20
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Running passive scan (spider)', 20, scan_db_id))
        conn.commit()
        conn.close()

        # Run the passive scan
        scanner.run_passive_scan()

        # Update status for active scan
        active_scans[scan_id]['status'] = 'Running active scan'
        active_scans[scan_id]['progress'] = 40
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Running active scan', 40, scan_db_id))
        conn.commit()
        conn.close()

        # Run the active scan
        scanner.run_active_scan()

        # Update status for processing results
        active_scans[scan_id]['status'] = 'Retrieving and processing results'
        active_scans[scan_id]['progress'] = 80
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Retrieving and processing results', 80, scan_db_id))
        conn.commit()
        conn.close()

        # Get scan results
        results = scanner.get_results()

        # Process results with risk engine
        risk_engine = RiskEngine(raw_results=results)
        parsed_alerts = risk_engine.parse_results()
        prioritized_alerts = risk_engine.prioritize_alerts(parsed_alerts)

        # Update status for storing results
        active_scans[scan_id]['status'] = 'Storing results in database'
        active_scans[scan_id]['progress'] = 90
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Storing results in database', 90, scan_db_id))
        conn.commit()

        # Count risk levels
        high_risk = sum(1 for alert in prioritized_alerts if alert['risk_level'] == 'High')
        medium_risk = sum(1 for alert in prioritized_alerts if alert['risk_level'] == 'Medium')
        low_risk = sum(1 for alert in prioritized_alerts if alert['risk_level'] == 'Low')
        info_risk = sum(1 for alert in prioritized_alerts if alert['risk_level'] == 'Informational')

        # Update scan record with results
        conn.execute('''
        UPDATE scans 
        SET total_alerts = ?, high_risk = ?, medium_risk = ?, low_risk = ?, 
            info_risk = ?, status = ?, progress = ?
        WHERE id = ?
        ''', (len(prioritized_alerts), high_risk, medium_risk, low_risk,
              info_risk, 'Completed', 100, scan_db_id))

        # Insert alert records
        for alert in prioritized_alerts:
            conn.execute('''
            INSERT INTO alerts (alert_name, risk_level, url, cwe_id, description, 
                              is_critical_endpoint, confidence, scan_date, scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['alert_name'],
                alert['risk_level'],
                alert['url'],
                alert.get('cwe_id', 'N/A'),
                alert.get('description', 'N/A'),
                1 if alert.get('is_critical_endpoint', False) else 0,
                alert.get('confidence', 'N/A'),
                datetime.now().isoformat(),
                scan_db_id
            ))

        conn.commit()
        conn.close()

        # Stop the ZAP container
        scanner.stop_zap_container()

        # Update final status
        active_scans[scan_id]['status'] = 'Completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['completed'] = True
        active_scans[scan_id]['scan_db_id'] = scan_db_id

    except Exception as e:
        # Handle any exceptions that occur during the scan
        error_msg = f'Error: {str(e)}'
        active_scans[scan_id]['status'] = error_msg
        active_scans[scan_id]['completed'] = True
        logger.error(f"Error in scan {scan_id}: {str(e)}")

        # Update database with error status
        try:
            conn = get_db_connection()
            conn.execute('UPDATE scans SET status = ? WHERE id = ?',
                        (error_msg, scan_db_id))
            conn.commit()
            conn.close()
        except Exception as db_error:
            logger.error(f"Error updating database with scan error: {db_error}")

        # Try to stop the container if it was started
        try:
            scanner.stop_zap_container()
        except:
            pass

@app.route('/export_alerts', methods=['GET'])
def export_alerts():
    """Export alerts to a CSV file."""
    try:
        conn = get_db_connection()
        alerts = conn.execute('SELECT * FROM alerts').fetchall()

        if not alerts:
            return jsonify({"error": "No alerts found"}), 404

        # Create a CSV file in memory
        output = io.StringIO()
        writer = csv.writer(output)

        # Write the header
        writer.writerow(['ID', 'Alert Name', 'Risk Level', 'URL', 'CWE ID', 'Description', 'Is Critical Endpoint', 'Confidence', 'Scan Date', 'Scan ID'])

        # Write the data
        for alert in alerts:
            writer.writerow([
                alert['id'],
                alert['alert_name'],
                alert['risk_level'],
                alert['url'],
                alert['cwe_id'],
                alert['description'],
                alert['is_critical_endpoint'],
                alert['confidence'],
                alert['scan_date'],
                alert['scan_id']
            ])

        output.seek(0)

        # Send the CSV file to the client
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name='alerts.csv'
        )
    except Exception as e:
        logger.error(f"Error exporting alerts: {e}")
        return jsonify({"error": "Error exporting alerts"}), 500

@app.route('/import_alerts', methods=['POST'])
def import_alerts():
    """Import alerts from a CSV file."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.endswith('.csv'):
        return jsonify({"error": "File is not a CSV"}), 400

    try:
        # Secure the filename
        filename = secure_filename(file.filename)

        # Read the CSV file
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)

        # Skip the header
        next(csv_input)

        conn = get_db_connection()

        # Insert each row into the database
        for row in csv_input:
            conn.execute('''
            INSERT INTO alerts (id, alert_name, risk_level, url, cwe_id, description, is_critical_endpoint, confidence, scan_date, scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                int(row[0]),  # ID
                row[1],       # Alert Name
                row[2],       # Risk Level
                row[3],       # URL
                row[4],       # CWE ID
                row[5],       # Description
                int(row[6]),  # Is Critical Endpoint
                row[7],       # Confidence
                row[8],       # Scan Date
                int(row[9])   # Scan ID
            ))

        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Alerts imported successfully"})
    except Exception as e:
        logger.error(f"Error importing alerts: {e}")
        return jsonify({"error": "Error importing alerts"}), 500

@app.route('/api/scans')
def get_scans():
    """API endpoint to get all scans with filtering options."""
    try:
        # Get query parameters for filtering
        risk_level = request.args.get('risk_level')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        target_url = request.args.get('target_url')

        conn = get_db_connection()

        # Build the query based on filters
        query = 'SELECT * FROM scans WHERE 1=1'
        params = []

        if risk_level:
            if risk_level == 'high':
                query += ' AND high_risk > 0'
            elif risk_level == 'medium':
                query += ' AND medium_risk > 0'
            elif risk_level == 'low':
                query += ' AND low_risk > 0'

        if start_date:
            query += ' AND scan_date >= ?'
            params.append(start_date)

        if end_date:
            query += ' AND scan_date <= ?'
            params.append(end_date)

        if target_url:
            query += ' AND target_url LIKE ?'
            params.append(f'%{target_url}%')

        query += ' ORDER BY scan_date DESC'

        scans = conn.execute(query, params).fetchall()
        conn.close()

        scans_list = [dict(row) for row in scans]
        return jsonify(scans_list)
    except Exception as e:
        logger.error(f"Error fetching scans: {e}")
        return jsonify({"error": "Error fetching scans"}), 500

@app.route('/api/statistics')
def get_statistics():
    """API endpoint to get dashboard statistics."""
    try:
        conn = get_db_connection()

        # Get overall statistics
        total_scans = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
        total_alerts = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        high_risk_alerts = conn.execute('SELECT COUNT(*) FROM alerts WHERE risk_level = "High"').fetchone()[0]
        recent_scans = conn.execute('SELECT COUNT(*) FROM scans WHERE date(scan_date) >= date("now", "-7 days")').fetchone()[0]

        # Get risk distribution
        risk_distribution = conn.execute('''
            SELECT risk_level, COUNT(*) as count 
            FROM alerts 
            GROUP BY risk_level
        ''').fetchall()

        # Get scan trends (last 30 days)
        scan_trends = conn.execute('''
            SELECT date(scan_date) as scan_day, COUNT(*) as count
            FROM scans 
            WHERE date(scan_date) >= date("now", "-30 days")
            GROUP BY date(scan_date)
            ORDER BY scan_day
        ''').fetchall()

        conn.close()

        return jsonify({
            "total_scans": total_scans,
            "total_alerts": total_alerts,
            "high_risk_alerts": high_risk_alerts,
            "recent_scans": recent_scans,
            "risk_distribution": [dict(row) for row in risk_distribution],
            "scan_trends": [dict(row) for row in scan_trends]
        })
    except Exception as e:
        logger.error(f"Error fetching statistics: {e}")
        return jsonify({"error": "Error fetching statistics"}), 500

@app.route('/api/alerts/search')
def search_alerts():
    """API endpoint to search alerts."""
    try:
        search_term = request.args.get('q', '')
        risk_level = request.args.get('risk_level')
        limit = int(request.args.get('limit', 50))

        conn = get_db_connection()

        query = '''
            SELECT * FROM alerts 
            WHERE (alert_name LIKE ? OR description LIKE ? OR url LIKE ?)
        '''
        params = [f'%{search_term}%', f'%{search_term}%', f'%{search_term}%']

        if risk_level:
            query += ' AND risk_level = ?'
            params.append(risk_level)

        query += ' ORDER BY scan_date DESC LIMIT ?'
        params.append(limit)

        alerts = conn.execute(query, params).fetchall()
        conn.close()

        alerts_list = [dict(row) for row in alerts]
        return jsonify(alerts_list)
    except Exception as e:
        logger.error(f"Error searching alerts: {e}")
        return jsonify({"error": "Error searching alerts"}), 500

@app.route('/api/scan/<int:scan_id>/delete', methods=['DELETE'])
def delete_scan(scan_id):
    """API endpoint to delete a scan and its alerts."""
    try:
        conn = get_db_connection()

        # Check if scan exists
        scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
        if not scan:
            conn.close()
            return jsonify({"error": "Scan not found"}), 404

        # Delete associated alerts first
        conn.execute('DELETE FROM alerts WHERE scan_id = ?', (scan_id,))

        # Delete the scan
        conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))

        conn.commit()
        conn.close()

        logger.info(f"Scan {scan_id} deleted successfully")
        return jsonify({"success": True, "message": "Scan deleted successfully"})
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        return jsonify({"error": "Error deleting scan"}), 500

@app.route('/test_scan', methods=['POST'])
def test_scan():
    """Test scan functionality without actually running ZAP - for debugging."""
    target_url = request.form.get('target_url')
    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    try:
        # Test Docker connectivity
        import docker
        client = docker.from_env()
        logger.info("Docker client connected successfully")

        # Test if we can list containers
        containers = client.containers.list()
        logger.info(f"Found {len(containers)} running containers")

        # Test if we can pull the ZAP image (but don't start it)
        try:
            image = client.images.get('ghcr.io/zaproxy/zaproxy:stable')
            logger.info("ZAP image already exists locally")
        except docker.errors.ImageNotFound:
            logger.info("ZAP image not found locally, would need to pull")

        # Create a simple mock scan that completes quickly
        scan_id = str(uuid.uuid4())

        # Store mock results directly in database
        scan_date = datetime.now().isoformat()
        conn = get_db_connection()

        # Insert mock scan record
        conn.execute('''
        INSERT INTO scans (target_url, scan_date, total_alerts, high_risk, medium_risk, low_risk, info_risk)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (target_url, scan_date, 3, 1, 1, 1, 0))

        scan_db_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

        # Insert mock alerts
        mock_alerts = [
            ('Cross-Site Scripting (XSS)', 'High', f'{target_url}/search', '79', 'Potential XSS vulnerability detected', 1, 'High'),
            ('SQL Injection', 'Medium', f'{target_url}/login', '89', 'Potential SQL injection point', 1, 'Medium'),
            ('Missing Security Headers', 'Low', target_url, '16', 'Security headers not configured', 0, 'Low')
        ]

        for alert in mock_alerts:
            conn.execute('''
            INSERT INTO alerts (alert_name, risk_level, url, cwe_id, description, is_critical_endpoint, confidence, scan_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', alert + (scan_date,))

        conn.commit()
        conn.close()

        logger.info(f"Mock scan completed successfully with database ID {scan_db_id}")

        return jsonify({
            "success": True,
            "message": "Test scan completed successfully",
            "scan_db_id": scan_db_id,
            "docker_status": "OK",
            "target_url": target_url
        })

    except Exception as e:
        logger.error(f"Test scan failed: {e}", exc_info=True)
        return jsonify({"error": f"Test failed: {str(e)}"}), 500

@app.route('/schedule')
def schedule_page():
    """Renders the scan scheduling page."""
    return render_template('schedule.html')

@app.route('/api/schedules', methods=['GET'])
def get_schedules():
    """Get all scheduled scans."""
    try:
        conn = get_db_connection()
        schedules = conn.execute('SELECT * FROM scheduled_scans ORDER BY created_at DESC').fetchall()
        conn.close()
        return jsonify([dict(schedule) for schedule in schedules])
    except Exception as e:
        logger.error(f"Error fetching schedules: {e}")
        return jsonify({"error": "Error fetching schedules"}), 500

@app.route('/api/schedules', methods=['POST'])
def create_schedule():
    """Create a new scheduled scan."""
    try:
        data = request.json
        now = datetime.now()

        # Calculate next scan time
        schedule_time = datetime.strptime(data['schedule_time'], '%H:%M').time()
        next_scan = calculate_next_scan_time(
            schedule_type=data['schedule_type'],
            schedule_time=schedule_time,
            schedule_day=data.get('schedule_day')
        )

        conn = get_db_connection()
        cursor = conn.execute('''
            INSERT INTO scheduled_scans (
                target_url, schedule_type, schedule_time, schedule_day,
                next_scan_date, created_at, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['target_url'],
            data['schedule_type'],
            data['schedule_time'],
            data.get('schedule_day'),
            next_scan.isoformat(),
            now.isoformat(),
            data.get('description', '')
        ))

        schedule_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Add to scheduler
        add_scan_to_scheduler(schedule_id, data['schedule_type'], schedule_time, data.get('schedule_day'))

        return jsonify({
            "success": True,
            "message": "Schedule created successfully",
            "id": schedule_id
        })
    except Exception as e:
        logger.error(f"Error creating schedule: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/schedules/<int:schedule_id>/toggle', methods=['POST'])
def toggle_schedule(schedule_id):
    """Toggle a scheduled scan active/inactive."""
    try:
        conn = get_db_connection()
        schedule = conn.execute('SELECT is_active FROM scheduled_scans WHERE id = ?',
                              (schedule_id,)).fetchone()

        if not schedule:
            conn.close()
            return jsonify({"error": "Schedule not found"}), 404

        new_status = not schedule['is_active']
        conn.execute('UPDATE scheduled_scans SET is_active = ? WHERE id = ?',
                    (new_status, schedule_id))
        conn.commit()
        conn.close()

        if new_status:
            # Reactivate in scheduler
            schedule = get_schedule_by_id(schedule_id)
            if schedule:
                add_scan_to_scheduler(
                    schedule_id,
                    schedule['schedule_type'],
                    datetime.strptime(schedule['schedule_time'], '%H:%M').time(),
                    schedule.get('schedule_day')
                )
        else:
            # Remove from scheduler
            job_id = f"scan_{schedule_id}"
            if scheduler.get_job(job_id):
                scheduler.remove_job(job_id)

        return jsonify({
            "success": True,
            "message": f"Schedule {'activated' if new_status else 'deactivated'} successfully"
        })
    except Exception as e:
        logger.error(f"Error toggling schedule: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/schedules/<int:schedule_id>', methods=['DELETE'])
def delete_schedule(schedule_id):
    """Delete a scheduled scan."""
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM scheduled_scans WHERE id = ?', (schedule_id,))
        conn.commit()
        conn.close()

        # Remove from scheduler
        job_id = f"scan_{schedule_id}"
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)

        return jsonify({
            "success": True,
            "message": "Schedule deleted successfully"
        })
    except Exception as e:
        logger.error(f"Error deleting schedule: {e}")
        return jsonify({"error": str(e)}), 500

def calculate_next_scan_time(schedule_type, schedule_time, schedule_day=None):
    """
    Calculate the next execution time for a scheduled scan.

    Args:
        schedule_type (str): Type of schedule ('daily', 'weekly', or 'monthly')
        schedule_time (time): Time of day to run the scan
        schedule_day (str, optional): Day of week for weekly scans or day of month for monthly scans

    Returns:
        datetime: The next scheduled execution time
    """
    now = datetime.now()
    today = now.date()

    # Create a datetime for today at the scheduled time
    next_scan = datetime.combine(today, schedule_time)

    # If that time has passed today, start from tomorrow
    if next_scan <= now:
        next_scan += timedelta(days=1)

    if schedule_type == 'weekly' and schedule_day:
        # Convert day name to day number (0 = Monday, 6 = Sunday)
        target_day = time.strptime(schedule_day, '%A').tm_wday
        current_day = next_scan.weekday()
        days_ahead = target_day - current_day
        if days_ahead <= 0:  # Target day has passed this week
            days_ahead += 7
        next_scan += timedelta(days=days_ahead)

    elif schedule_type == 'monthly' and schedule_day:
        target_day = int(schedule_day)
        # Start with the first occurrence of the target day
        if next_scan.day > target_day:  # We've passed target day this month
            # Move to first day of next month
            if next_scan.month == 12:
                next_scan = next_scan.replace(year=next_scan.year + 1, month=1, day=1)
            else:
                next_scan = next_scan.replace(month=next_scan.month + 1, day=1)
        # Set the target day, handling months with fewer days
        while True:
            try:
                next_scan = next_scan.replace(day=target_day)
                break
            except ValueError:  # Month doesn't have this day
                target_day -= 1

    return next_scan

def add_scan_to_scheduler(schedule_id, schedule_type, schedule_time, schedule_day=None):
    """
    Add or update a scheduled scan in the APScheduler system.

    Args:
        schedule_id (int): Database ID of the schedule
        schedule_type (str): Type of schedule ('daily', 'weekly', or 'monthly')
        schedule_time (time): Time of day to run the scan
        schedule_day (str, optional): Day of week for weekly scans or day of month for monthly scans
    """
    job_id = f"scan_{schedule_id}"

    # Remove existing job if it exists
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    # Create the cron trigger based on schedule type
    if schedule_type == 'daily':
        trigger = CronTrigger(
            hour=schedule_time.hour,
            minute=schedule_time.minute
        )
    elif schedule_type == 'weekly':
        # Convert day name to day number (0 = Monday, 6 = Sunday)
        day_number = time.strptime(schedule_day, '%A').tm_wday
        trigger = CronTrigger(
            day_of_week=day_number,
            hour=schedule_time.hour,
            minute=schedule_time.minute
        )
    else:  # monthly
        trigger = CronTrigger(
            day=schedule_day,
            hour=schedule_time.hour,
            minute=schedule_time.minute
        )

    # Add the job to the scheduler
    scheduler.add_job(
        func=run_scheduled_scan,
        trigger=trigger,
        id=job_id,
        args=[schedule_id],
        replace_existing=True
    )

def run_scheduled_scan(schedule_id):
    """
    Execute a scheduled scan.

    This function is called automatically by the scheduler when a scan is due.
    It retrieves the scan configuration, executes the scan, and updates the
    schedule's last run time.

    Args:
        schedule_id (int): Database ID of the schedule to execute
    """
    try:
        # Get schedule details
        schedule = get_schedule_by_id(schedule_id)
        if not schedule or not schedule['is_active']:
            return

        # Generate a unique ID for this scan
        scan_id = str(uuid.uuid4())

        # Start the scan
        run_scan(scan_id, schedule['target_url'], schedule_id)

        # Update last scan date
        conn = get_db_connection()
        conn.execute('''
            UPDATE scheduled_scans 
            SET last_scan_date = ? 
            WHERE id = ?
        ''', (datetime.now().isoformat(), schedule_id))
        conn.commit()
        conn.close()

    except Exception as e:
        logger.error(f"Error running scheduled scan {schedule_id}: {e}")

def get_schedule_by_id(schedule_id):
    """Get a schedule by its ID."""
    try:
        conn = get_db_connection()
        schedule = conn.execute('SELECT * FROM scheduled_scans WHERE id = ?',
                              (schedule_id,)).fetchone()
        conn.close()
        return dict(schedule) if schedule else None
    except Exception as e:
        logger.error(f"Error fetching schedule {schedule_id}: {e}")
        return None

# Update run_scan to handle scheduled scans
def run_scan(scan_id, target_url, scheduled_scan_id=None):
    """
    Run a ZAP scan in a background thread.

    Args:
        scan_id (str): Unique identifier for the scan
        target_url (str): The URL to be scanned
        scheduled_scan_id (int, optional): ID of the associated scheduled scan, if any
    """
    try:
        logger.info(f"Starting scan {scan_id} for {target_url}")

        # Create initial scan record in database with local time
        conn = get_db_connection()
        conn.execute('''
        INSERT INTO scans (target_url, scan_date, status, progress)
        VALUES (?, ?, ?, ?)
        ''', (target_url, get_local_datetime(), 'Initializing', 0))
        conn.commit()

        # Get the scan database ID
        scan_db_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()

        # Update active scans dictionary
        active_scans[scan_id] = {
            'target_url': target_url,
            'status': 'Starting ZAP container',
            'progress': 5,
            'completed': False,
            'scan_db_id': scan_db_id
        }

        # Update database with status
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Starting ZAP container', 5, scan_db_id))
        conn.commit()
        conn.close()

        logger.info(f"Scan {scan_id}: Starting ZAP container")

        # Use the fixed API key that matches the ZAP container configuration
        api_key = "zap-api-key-12345"
        logger.info(f"Scan {scan_id}: Using fixed API key")

        # Initialize the scanner
        scanner = ZAPScanner(target_url=target_url, api_key=api_key)
        logger.info(f"Scan {scan_id}: ZAP Scanner initialized")

        # Check ZAP readiness
        scanner.start_zap_container()
        logger.info(f"Scan {scan_id}: ZAP container started successfully")

        # Update status for passive scan
        active_scans[scan_id]['status'] = 'Running passive scan (spider)'
        active_scans[scan_id]['progress'] = 20
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Running passive scan (spider)', 20, scan_db_id))
        conn.commit()
        conn.close()

        # Run the passive scan
        scanner.run_passive_scan()

        # Update status for active scan
        active_scans[scan_id]['status'] = 'Running active scan'
        active_scans[scan_id]['progress'] = 40
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Running active scan', 40, scan_db_id))
        conn.commit()
        conn.close()

        # Run the active scan
        scanner.run_active_scan()

        # Update status for processing results
        active_scans[scan_id]['status'] = 'Retrieving and processing results'
        active_scans[scan_id]['progress'] = 80
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Retrieving and processing results', 80, scan_db_id))
        conn.commit()
        conn.close()

        # Get scan results
        results = scanner.get_results()

        # Process results with risk engine
        risk_engine = RiskEngine(raw_results=results)
        parsed_alerts = risk_engine.parse_results()
        prioritized_alerts = risk_engine.prioritize_alerts(parsed_alerts)

        # Update status for storing results
        active_scans[scan_id]['status'] = 'Storing results in database'
        active_scans[scan_id]['progress'] = 90
        conn = get_db_connection()
        conn.execute('UPDATE scans SET status = ?, progress = ? WHERE id = ?',
                    ('Storing results in database', 90, scan_db_id))
        conn.commit()

        # Count risk levels
        high_risk = sum(1 for alert in prioritized_alerts if alert['risk_level'] == 'High')
        medium_risk = sum(1 for alert in prioritized_alerts if alert['risk_level'] == 'Medium')
        low_risk = sum(1 for alert in prioritized_alerts if alert['risk_level'] == 'Low')
        info_risk = sum(1 for alert in prioritized_alerts if alert['risk_level'] == 'Informational')

        # Update scan record with results
        conn.execute('''
        UPDATE scans 
        SET total_alerts = ?, high_risk = ?, medium_risk = ?, low_risk = ?, 
            info_risk = ?, status = ?, progress = ?
        WHERE id = ?
        ''', (len(prioritized_alerts), high_risk, medium_risk, low_risk,
              info_risk, 'Completed', 100, scan_db_id))

        # Insert alert records
        for alert in prioritized_alerts:
            conn.execute('''
            INSERT INTO alerts (alert_name, risk_level, url, cwe_id, description, 
                              is_critical_endpoint, confidence, scan_date, scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['alert_name'],
                alert['risk_level'],
                alert['url'],
                alert.get('cwe_id', 'N/A'),
                alert.get('description', 'N/A'),
                1 if alert.get('is_critical_endpoint', False) else 0,
                alert.get('confidence', 'N/A'),
                datetime.now().isoformat(),
                scan_db_id
            ))

        conn.commit()
        conn.close()

        # Stop the ZAP container
        scanner.stop_zap_container()

        # Update final status
        active_scans[scan_id]['status'] = 'Completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['completed'] = True
        active_scans[scan_id]['scan_db_id'] = scan_db_id

    except Exception as e:
        # Handle any exceptions that occur during the scan
        error_msg = f'Error: {str(e)}'
        active_scans[scan_id]['status'] = error_msg
        active_scans[scan_id]['completed'] = True
        logger.error(f"Error in scan {scan_id}: {str(e)}")

        # Update database with error status
        try:
            conn = get_db_connection()
            conn.execute('UPDATE scans SET status = ? WHERE id = ?',
                        (error_msg, scan_db_id))
            conn.commit()
            conn.close()
        except Exception as db_error:
            logger.error(f"Error updating database with scan error: {db_error}")

        # Try to stop the container if it was started
        try:
            scanner.stop_zap_container()
        except:
            pass

if __name__ == '__main__':
    # Initialize the database
    init_db()

    # Insert sample data for demonstration
    conn = get_db_connection()

    # Check if we already have data
    count = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]

    if count == 0:
        # Insert sample data for demonstration
        sample_scan_date = datetime.now().isoformat()

        # Insert a sample scan
        conn.execute('''
        INSERT INTO scans (target_url, scan_date, total_alerts, high_risk, medium_risk, low_risk, info_risk)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('http://example.com', sample_scan_date, 2, 1, 1, 0, 0))

        # Insert sample alerts
        conn.execute('''
        INSERT INTO alerts (alert_name, risk_level, url, cwe_id, description, is_critical_endpoint, confidence, scan_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('SQL Injection', 'High', 'http://example.com/login', '89', 'A potential SQLi vulnerability', 1, 'High', sample_scan_date))

        conn.execute('''
        INSERT INTO alerts (alert_name, risk_level, url, cwe_id, description, is_critical_endpoint, confidence, scan_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('XSS Reflected', 'Medium', 'http://example.com/search', '79', 'Reflected Cross-Site Scripting', 0, 'Medium', sample_scan_date))

        conn.commit()
        logger.info("Sample data inserted.")

    conn.close()

    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
