#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Flask Web Dashboard
"""
import os
import json
import threading
import uuid
from datetime import datetime


from config import Config, Colors
from core.engine import AtomicEngine, Finding
from utils.database import Database, ScanModel, FindingModel, SQLALCHEMY_AVAILABLE

try:
    from flask import (
        Flask, render_template, request, jsonify, send_from_directory
    )
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), 'static'),
)
# Set ATOMIC_SECRET_KEY env var to persist sessions across restarts.
# Without it a random key is generated on each startup, invalidating sessions.
app.config['SECRET_KEY'] = os.environ.get('ATOMIC_SECRET_KEY', uuid.uuid4().hex)

if FLASK_AVAILABLE:
    CORS(app)

_active_scans = {}


def _get_db():
    """Get a database instance."""
    if not SQLALCHEMY_AVAILABLE:
        return None
    try:
        return Database()
    except Exception:
        return None


def _run_scan(scan_id, target, config):
    """Background scan runner."""
    _active_scans[scan_id] = {
        'status': 'running',
        'target': target,
        'start_time': datetime.utcnow().isoformat(),
        'findings': 0,
    }
    try:
        engine = AtomicEngine(config)
        engine.scan_id = scan_id
        engine.scan(target)
        engine.generate_reports()
        _active_scans[scan_id]['status'] = 'completed'
        _active_scans[scan_id]['findings'] = len(engine.findings)
        _active_scans[scan_id]['end_time'] = datetime.utcnow().isoformat()
    except Exception as exc:
        _active_scans[scan_id]['status'] = 'failed'
        _active_scans[scan_id]['error'] = str(exc)
        _active_scans[scan_id]['end_time'] = datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def dashboard():
    """Render the main dashboard page."""
    return render_template('index.html', version=Config.VERSION)


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """Return a list of all past scans."""
    db = _get_db()
    if db is None:
        return jsonify({'status': 'error', 'data': 'Database unavailable'}), 503

    try:
        session = db.Session()
        scans = session.query(ScanModel).order_by(ScanModel.start_time.desc()).all()
        data = []
        for s in scans:
            data.append({
                'id': s.id,
                'scan_id': s.scan_id,
                'target': s.target,
                'start_time': s.start_time.isoformat() if s.start_time else None,
                'end_time': s.end_time.isoformat() if s.end_time else None,
                'findings_count': s.findings_count,
                'total_requests': s.total_requests,
            })
        session.close()
        return jsonify({'status': 'success', 'data': data})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Return details and findings for a specific scan."""
    db = _get_db()
    if db is None:
        return jsonify({'status': 'error', 'data': 'Database unavailable'}), 503

    try:
        session = db.Session()
        scan = session.query(ScanModel).filter_by(scan_id=scan_id).first()
        if not scan:
            session.close()
            return jsonify({'status': 'error', 'data': 'Scan not found'}), 404

        findings = session.query(FindingModel).filter_by(scan_id=scan_id).all()
        findings_data = []
        for f in findings:
            findings_data.append({
                'id': f.id,
                'technique': f.technique,
                'severity': f.severity,
                'confidence': f.confidence,
                'url': f.url,
                'param': f.param,
                'payload': f.payload,
                'evidence': f.evidence,
                'mitre_id': f.mitre_id,
                'cwe_id': f.cwe_id,
                'cvss': f.cvss,
                'extracted_data': f.extracted_data,
            })

        data = {
            'scan_id': scan.scan_id,
            'target': scan.target,
            'start_time': scan.start_time.isoformat() if scan.start_time else None,
            'end_time': scan.end_time.isoformat() if scan.end_time else None,
            'findings_count': scan.findings_count,
            'total_requests': scan.total_requests,
            'findings': findings_data,
        }
        session.close()
        return jsonify({'status': 'success', 'data': data})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan in the background."""
    body = request.get_json(silent=True)
    if not body or 'target' not in body:
        return jsonify({'status': 'error', 'data': 'Missing target'}), 400

    target = body['target'].strip()
    if not target.startswith(('http://', 'https://')):
        return jsonify({
            'status': 'error',
            'data': 'Invalid URL format – must start with http:// or https://'
        }), 400

    scan_id = str(uuid.uuid4())[:8]
    modules = body.get('modules', [])
    evasion = body.get('evasion', 'none')
    depth = body.get('depth', Config.MAX_DEPTH)
    threads = body.get('threads', Config.MAX_THREADS)
    full_scan = body.get('full_scan', False)

    all_module_keys = [
        'sqli', 'xss', 'lfi', 'cmdi', 'ssrf', 'ssti',
        'xxe', 'idor', 'nosql', 'cors', 'jwt', 'upload',
    ]
    modules_dict = {}
    for key in all_module_keys:
        modules_dict[key] = full_scan or (key in modules)
    modules_dict.update({
        'recon': full_scan, 'subdomains': full_scan,
        'tech_detect': full_scan, 'dir_brute': full_scan,
        'shell': False, 'dump': False, 'os_shell': False,
        'brute': False, 'exploit_chain': False, 'ports': None,
    })

    config = {
        'target': target,
        'modules': modules_dict,
        'evasion': evasion,
        'depth': int(depth),
        'threads': int(threads),
        'verbose': False,
        'quiet': True,
        'timeout': Config.TIMEOUT,
        'delay': Config.REQUEST_DELAY,
        'waf_bypass': False,
        'tor': False,
        'proxy': None,
        'rotate_proxy': False,
        'rotate_ua': True,
        'output_dir': Config.REPORTS_DIR,
    }

    thread = threading.Thread(
        target=_run_scan, args=(scan_id, target, config), daemon=True
    )
    thread.start()

    return jsonify({
        'status': 'success',
        'data': {'scan_id': scan_id, 'target': target, 'message': 'Scan started'},
    })


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def scan_status(scan_id):
    """Return the current status of a scan."""
    if scan_id in _active_scans:
        return jsonify({'status': 'success', 'data': _active_scans[scan_id]})

    db = _get_db()
    if db is not None:
        try:
            session = db.Session()
            scan = session.query(ScanModel).filter_by(scan_id=scan_id).first()
            session.close()
            if scan:
                return jsonify({
                    'status': 'success',
                    'data': {'status': 'completed', 'target': scan.target,
                             'findings': scan.findings_count},
                })
        except Exception:
            pass

    return jsonify({'status': 'error', 'data': 'Scan not found'}), 404


@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan and its findings from the database."""
    db = _get_db()
    if db is None:
        return jsonify({'status': 'error', 'data': 'Database unavailable'}), 503

    try:
        session = db.Session()
        scan = session.query(ScanModel).filter_by(scan_id=scan_id).first()
        if not scan:
            session.close()
            return jsonify({'status': 'error', 'data': 'Scan not found'}), 404

        session.query(FindingModel).filter_by(scan_id=scan_id).delete()
        session.delete(scan)
        session.commit()
        session.close()

        _active_scans.pop(scan_id, None)
        return jsonify({'status': 'success', 'data': 'Scan deleted'})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/findings/<scan_id>', methods=['GET'])
def get_findings(scan_id):
    """Return all findings for a given scan."""
    db = _get_db()
    if db is None:
        return jsonify({'status': 'error', 'data': 'Database unavailable'}), 503

    try:
        session = db.Session()
        findings = session.query(FindingModel).filter_by(scan_id=scan_id).all()
        data = []
        for f in findings:
            data.append({
                'id': f.id,
                'technique': f.technique,
                'severity': f.severity,
                'confidence': f.confidence,
                'url': f.url,
                'param': f.param,
                'payload': f.payload,
                'evidence': f.evidence,
                'mitre_id': f.mitre_id,
                'cwe_id': f.cwe_id,
                'cvss': f.cvss,
                'extracted_data': f.extracted_data,
            })
        session.close()
        return jsonify({'status': 'success', 'data': data})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/report/<scan_id>/<fmt>', methods=['GET'])
def download_report(scan_id, fmt):
    """Download a generated report file."""
    allowed_formats = ('html', 'json', 'csv', 'txt')
    if fmt not in allowed_formats:
        return jsonify({
            'status': 'error',
            'data': f'Invalid format. Allowed: {", ".join(allowed_formats)}',
        }), 400

    filename = f'report_{scan_id}.{fmt}'
    reports_dir = Config.REPORTS_DIR

    if not os.path.isfile(os.path.join(reports_dir, filename)):
        return jsonify({'status': 'error', 'data': 'Report not found'}), 404

    return send_from_directory(reports_dir, filename, as_attachment=True)


@app.route('/api/shells', methods=['GET'])
def list_shells():
    """Return active shells from the database."""
    db = _get_db()
    if db is None:
        return jsonify({'status': 'success', 'data': []})

    try:
        shells = db.get_shells()
        data = []
        for s in shells:
            data.append({
                'shell_id': s.get('shell_id', ''),
                'url': s.get('url', ''),
                'shell_type': s.get('shell_type', ''),
                'created_at': str(s.get('created_at', '')),
            })
        return jsonify({'status': 'success', 'data': data})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Return dashboard statistics."""
    db = _get_db()
    stats = {
        'total_scans': 0,
        'total_findings': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0,
        'active_scans': len(
            [s for s in _active_scans.values() if s['status'] == 'running']
        ),
    }

    if db is not None:
        try:
            session = db.Session()
            stats['total_scans'] = session.query(ScanModel).count()
            stats['total_findings'] = session.query(FindingModel).count()
            for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
                count = (
                    session.query(FindingModel)
                    .filter(FindingModel.severity == severity)
                    .count()
                )
                stats[severity.lower()] = count
            session.close()
        except Exception:
            pass

    return jsonify({'status': 'success', 'data': stats})


# ---------------------------------------------------------------------------
# App factory & runner
# ---------------------------------------------------------------------------

def create_app(host='0.0.0.0', port=5000, debug=False):
    """Configure and return the Flask application and a convenience runner."""
    app.config['HOST'] = host
    app.config['PORT'] = port
    app.config['DEBUG'] = debug

    os.makedirs(Config.REPORTS_DIR, exist_ok=True)

    def run_app():
        print(f"{Colors.info(f'Starting ATOMIC Dashboard on http://{host}:{port}')}")
        print(f"{Colors.warning('FOR AUTHORIZED TESTING ONLY')}")
        app.run(host=host, port=port, debug=debug)

    return app, run_app


if __name__ == '__main__':
    _, runner = create_app(debug=os.environ.get('FLASK_DEBUG', '').lower() == '1')
    runner()
