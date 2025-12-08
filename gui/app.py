"""
Flask Web GUI for Web Security Scanner
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import threading
from datetime import datetime

from scanners.sql_injection import SQLInjectionScanner
from scanners.xss_scanner import XSSScanner
from utils.report_generator import ReportGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Store scan results in memory (for demo purposes)
scan_results = {}
scan_status = {}


@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.get_json()
    url = data.get('url')
    scan_type = data.get('type', 'all')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Generate scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Initialize scan status
    scan_status[scan_id] = {
        'status': 'running',
        'progress': 0,
        'message': 'Initializing scan...'
    }
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(scan_id, url, scan_type))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_status[scan_id])


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    return jsonify(scan_results[scan_id])


@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def download_report(scan_id):
    """Download scan report"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    # Generate report
    report_gen = ReportGenerator()
    report_path = f"reports/{scan_id}_report.html"
    
    # Create reports directory if not exists
    os.makedirs('reports', exist_ok=True)
    
    report_gen.generate(scan_results[scan_id]['vulnerabilities'], f"reports/{scan_id}_report")
    
    return send_file(report_path, as_attachment=True)


def run_scan(scan_id, url, scan_type):
    """Run scan in background"""
    try:
        results = []
        
        # SQL Injection scan
        if scan_type in ['sqli', 'all']:
            scan_status[scan_id].update({
                'status': 'running',
                'progress': 25,
                'message': 'Running SQL Injection scan...'
            })
            
            sqli_scanner = SQLInjectionScanner(url)
            sqli_results = sqli_scanner.scan()
            results.extend(sqli_results)
        
        # XSS scan
        if scan_type in ['xss', 'all']:
            scan_status[scan_id].update({
                'status': 'running',
                'progress': 60,
                'message': 'Running XSS scan...'
            })
            
            xss_scanner = XSSScanner(url)
            xss_results = xss_scanner.scan()
            results.extend(xss_results)
        
        # Store results
        scan_results[scan_id] = {
            'url': url,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': results,
            'total_vulnerabilities': len(results),
            'high_severity': len([v for v in results if v.get('severity') == 'High']),
            'medium_severity': len([v for v in results if v.get('severity') == 'Medium']),
            'low_severity': len([v for v in results if v.get('severity') == 'Low'])
        }
        
        # Update status
        scan_status[scan_id].update({
            'status': 'completed',
            'progress': 100,
            'message': f'Scan completed. Found {len(results)} vulnerability(ies).'
        })
        
    except Exception as e:
        scan_status[scan_id].update({
            'status': 'error',
            'progress': 0,
            'message': f'Error: {str(e)}'
        })


def start_gui():
    """Start Flask web server"""
    print("Starting Web GUI on http://127.0.0.1:5000")
    print("Press Ctrl+C to stop")
    app.run(debug=False, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    start_gui()
