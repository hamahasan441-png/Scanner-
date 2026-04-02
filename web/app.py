#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Flask Web Dashboard
"""
import os
import json
import logging
import re
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps


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

logger = logging.getLogger(__name__)

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
_scans_lock = threading.Lock()

# Scan-ID must be a hex UUID (no slashes, dots, or traversal chars).
_SAFE_SCAN_ID = re.compile(r'^[a-zA-Z0-9_-]+$')


# ---------------------------------------------------------------------------
# API-key authentication
# ---------------------------------------------------------------------------
# Set ATOMIC_API_KEY env var to require an API key for all /api/* endpoints.
# When the env var is unset, authentication is disabled (open access).
_API_KEY = os.environ.get('ATOMIC_API_KEY', '')


def _require_api_key(f):
    """Decorator that rejects requests lacking a valid API key (when set)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _API_KEY:
            return f(*args, **kwargs)
        provided = (
            request.headers.get('X-API-Key', '')
            or request.args.get('api_key', '')
        )
        if provided != _API_KEY:
            return jsonify({'status': 'error', 'data': 'Invalid or missing API key'}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter
# ---------------------------------------------------------------------------
_RATE_WINDOW = 60          # seconds
_RATE_MAX_REQUESTS = 60    # max requests per window per IP
_RATE_CLEANUP_EVERY = 100  # prune stale IPs every N requests

_rate_counters: dict = defaultdict(list)
_rate_lock = threading.Lock()
_rate_request_count = 0


def _rate_limit(f):
    """Decorator that applies a per-IP request rate limit."""
    @wraps(f)
    def decorated(*args, **kwargs):
        global _rate_request_count
        client_ip = request.remote_addr or '0.0.0.0'
        now = time.monotonic()
        with _rate_lock:
            # Prune expired timestamps for this IP
            _rate_counters[client_ip] = [
                t for t in _rate_counters[client_ip] if now - t < _RATE_WINDOW
            ]
            if len(_rate_counters[client_ip]) >= _RATE_MAX_REQUESTS:
                return jsonify({
                    'status': 'error',
                    'data': 'Rate limit exceeded. Try again later.',
                }), 429
            _rate_counters[client_ip].append(now)

            # Periodically purge IPs with no recent activity
            _rate_request_count += 1
            if _rate_request_count >= _RATE_CLEANUP_EVERY:
                _rate_request_count = 0
                stale = [
                    ip for ip, ts in _rate_counters.items()
                    if not ts or (now - ts[-1]) >= _RATE_WINDOW
                ]
                for ip in stale:
                    del _rate_counters[ip]
        return f(*args, **kwargs)
    return decorated


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
    with _scans_lock:
        _active_scans[scan_id] = {
            'status': 'running',
            'target': target,
            'start_time': datetime.now(timezone.utc).isoformat(),
            'findings': 0,
            'engine': None,
            'pipeline': {'phase': 'init', 'events': []},
        }
    try:
        engine = AtomicEngine(config)
        engine.scan_id = scan_id
        with _scans_lock:
            _active_scans[scan_id]['engine'] = engine
        engine.scan(target)
        engine.generate_reports()
        with _scans_lock:
            _active_scans[scan_id]['status'] = 'completed'
            _active_scans[scan_id]['findings'] = len(engine.findings)
            _active_scans[scan_id]['end_time'] = datetime.now(timezone.utc).isoformat()
            _active_scans[scan_id]['pipeline'] = engine.get_pipeline_state()
    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        with _scans_lock:
            _active_scans[scan_id]['status'] = 'failed'
            _active_scans[scan_id]['error'] = str(exc)
            _active_scans[scan_id]['end_time'] = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def dashboard():
    """Render the main dashboard page."""
    return render_template('index.html', version=Config.VERSION)


@app.route('/api/scans', methods=['GET'])
@_require_api_key
@_rate_limit
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
@_require_api_key
@_rate_limit
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
@_require_api_key
@_rate_limit
def start_scan():
    """Start a new scan in the background.

    Accepts either a single target (``target`` field) or a list of targets
    (``targets`` field) so users can launch a file-based batch scan from the
    dashboard.
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({'status': 'error', 'data': 'Missing JSON body'}), 400

    # Accept either a single 'target' string or a 'targets' list
    raw_targets = []
    if 'targets' in body and isinstance(body['targets'], list):
        raw_targets = [t.strip() for t in body['targets'] if isinstance(t, str) and t.strip()]
    elif 'target' in body:
        raw_targets = [body['target'].strip()]

    if not raw_targets:
        return jsonify({'status': 'error', 'data': 'Missing target or targets'}), 400

    # Validate URLs
    valid_targets = []
    invalid = []
    for t in raw_targets:
        if t.startswith(('http://', 'https://')):
            valid_targets.append(t)
        else:
            invalid.append(t)

    if not valid_targets:
        return jsonify({
            'status': 'error',
            'data': 'No valid URLs – each must start with http:// or https://'
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

    auto_exploit = body.get('auto_exploit', False)
    modules_dict.update({
        'recon': full_scan or body.get('recon', False),
        'subdomains': full_scan,
        'tech_detect': full_scan,
        'dir_brute': full_scan,
        'shell': False, 'dump': False, 'os_shell': False,
        'brute': body.get('brute', False),
        'exploit_chain': False,
        'ports': body.get('ports'),
        'auto_exploit': auto_exploit or full_scan,
    })

    # Launch one scan thread per valid target; share the same scan_id prefix
    scan_ids = []
    for idx, target in enumerate(valid_targets):
        if len(valid_targets) == 1:
            tid = scan_id
        else:
            tid = f"{scan_id}-{idx}"

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
            target=_run_scan, args=(tid, target, config), daemon=True
        )
        thread.start()
        scan_ids.append({'scan_id': tid, 'target': target})

    resp_data = {
        'scan_ids': scan_ids,
        'total_targets': len(valid_targets),
        'message': f'{len(valid_targets)} scan(s) started',
    }
    if invalid:
        resp_data['skipped'] = invalid

    return jsonify({'status': 'success', 'data': resp_data})


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
@_require_api_key
@_rate_limit
def scan_status(scan_id):
    """Return the current status of a scan including pipeline state."""
    if scan_id in _active_scans:
        info = dict(_active_scans[scan_id])
        # Add live pipeline data from engine
        engine = info.pop('engine', None)
        if engine and hasattr(engine, 'get_pipeline_state'):
            info['pipeline'] = engine.get_pipeline_state()
            info['findings'] = len(engine.findings)
        return jsonify({'status': 'success', 'data': info})

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
@_require_api_key
@_rate_limit
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
@_require_api_key
@_rate_limit
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
@_require_api_key
@_rate_limit
def download_report(scan_id, fmt):
    """Download a generated report file."""
    allowed_formats = ('html', 'json', 'csv', 'txt')
    if fmt not in allowed_formats:
        return jsonify({
            'status': 'error',
            'data': f'Invalid format. Allowed: {", ".join(allowed_formats)}',
        }), 400

    # Reject scan_ids containing path-traversal characters
    if not _SAFE_SCAN_ID.match(scan_id):
        return jsonify({'status': 'error', 'data': 'Invalid scan ID'}), 400

    filename = f'report_{scan_id}.{fmt}'
    reports_dir = os.path.realpath(Config.REPORTS_DIR)

    # Ensure resolved path stays within reports directory
    full_path = os.path.realpath(os.path.join(reports_dir, filename))
    if not full_path.startswith(reports_dir + os.sep) and full_path != reports_dir:
        return jsonify({'status': 'error', 'data': 'Invalid scan ID'}), 400

    if not os.path.isfile(full_path):
        return jsonify({'status': 'error', 'data': 'Report not found'}), 404

    return send_from_directory(reports_dir, filename, as_attachment=True)


@app.route('/api/shells', methods=['GET'])
@_require_api_key
@_rate_limit
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


@app.route('/api/exploit/<scan_id>', methods=['POST'])
@_require_api_key
@_rate_limit
def run_post_exploit(scan_id):
    """Run AI-driven post-exploitation on confirmed findings for a scan.

    Reads findings from the database, instantiates the PostExploitEngine,
    and returns the exploitation results.
    """
    scan_info = _active_scans.get(scan_id)
    if scan_info is None:
        return jsonify({'status': 'error',
                        'message': 'Scan not found or not active'}), 404

    engine = scan_info.get('engine')
    if engine is None or not engine.findings:
        return jsonify({'status': 'error',
                        'message': 'No confirmed findings to exploit'}), 400

    try:
        from core.post_exploit import PostExploitEngine
        post_engine = PostExploitEngine(engine)
        post_engine.run(engine.findings)
        summary = post_engine.get_summary()
        return jsonify({'status': 'success', 'data': summary})
    except Exception as exc:
        logger.error('Post-exploitation error: %s', exc)
        return jsonify({'status': 'error',
                        'message': 'Post-exploitation failed'}), 500


@app.route('/api/stats', methods=['GET'])
@_require_api_key
@_rate_limit
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
# Burp Suite-style tool endpoints
# ---------------------------------------------------------------------------

@app.route('/api/tools/decode', methods=['POST'])
@_require_api_key
@_rate_limit
def api_decode():
    """Decode data (auto-detect or specified encoding)."""
    body = request.get_json(silent=True) or {}
    data = body.get('data', '')
    encoding = body.get('encoding')
    if not data:
        return jsonify({'status': 'error', 'data': 'Missing data field'}), 400
    try:
        from utils.decoder import Decoder
        if encoding:
            result = Decoder.decode(data, encoding)
        else:
            result = Decoder.smart_decode(data)
        return jsonify({'status': 'success', 'data': {'result': result}})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/tools/encode', methods=['POST'])
@_require_api_key
@_rate_limit
def api_encode():
    """Encode data with a specified encoding type."""
    body = request.get_json(silent=True) or {}
    data = body.get('data', '')
    encoding = body.get('encoding', 'url')
    if not data:
        return jsonify({'status': 'error', 'data': 'Missing data field'}), 400
    try:
        from utils.decoder import Decoder
        result = Decoder.encode(data, encoding)
        return jsonify({'status': 'success', 'data': {'result': result, 'encoding': encoding}})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/tools/hash', methods=['POST'])
@_require_api_key
@_rate_limit
def api_hash():
    """Hash data with a specified algorithm."""
    body = request.get_json(silent=True) or {}
    data = body.get('data', '')
    algorithm = body.get('algorithm', 'sha256')
    if not data:
        return jsonify({'status': 'error', 'data': 'Missing data field'}), 400
    try:
        from utils.decoder import Decoder
        result = Decoder.hash_data(data, algorithm)
        return jsonify({'status': 'success', 'data': {'result': result, 'algorithm': algorithm}})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/tools/compare', methods=['POST'])
@_require_api_key
@_rate_limit
def api_compare():
    """Compare two texts or HTTP responses."""
    body = request.get_json(silent=True) or {}
    text1 = body.get('text1', '')
    text2 = body.get('text2', '')
    if not text1 and not text2:
        return jsonify({'status': 'error', 'data': 'Missing text1/text2 fields'}), 400
    try:
        from utils.comparer import Comparer
        comp = Comparer()
        ratio = comp.similarity_ratio(text1, text2)
        diff = comp.diff_text(text1, text2)
        return jsonify({
            'status': 'success',
            'data': {'similarity': ratio, 'diff': diff},
        })
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/tools/sequencer', methods=['POST'])
@_require_api_key
@_rate_limit
def api_sequencer():
    """Analyze token randomness/entropy."""
    body = request.get_json(silent=True) or {}
    tokens = body.get('tokens', [])
    if not tokens:
        return jsonify({'status': 'error', 'data': 'Missing tokens list'}), 400
    try:
        from utils.sequencer import Sequencer
        seq = Sequencer()
        seq.add_tokens(tokens)
        report = seq.generate_report()
        return jsonify({'status': 'success', 'data': report})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/tools/repeater', methods=['POST'])
@_require_api_key
@_rate_limit
def api_repeater():
    """Send an HTTP request via the Repeater tool."""
    body = request.get_json(silent=True) or {}
    method = body.get('method', 'GET').upper()
    url = body.get('url', '')
    headers = body.get('headers')
    req_body = body.get('body')
    if not url:
        return jsonify({'status': 'error', 'data': 'Missing url field'}), 400
    if not url.startswith(('http://', 'https://')):
        return jsonify({'status': 'error', 'data': 'URL must start with http:// or https://'}), 400
    try:
        from core.repeater import Repeater
        rep = Repeater(timeout=15)
        resp = rep.send(method, url, headers=headers, body=req_body)
        return jsonify({
            'status': 'success',
            'data': {
                'status_code': resp.status_code,
                'headers': resp.headers,
                'body': resp.body[:10000],
                'elapsed': resp.elapsed,
                'size': resp.size,
            },
        })
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/tools/encodings', methods=['GET'])
@_require_api_key
@_rate_limit
def api_list_encodings():
    """List all supported encodings."""
    try:
        from utils.decoder import Decoder
        return jsonify({'status': 'success', 'data': Decoder.list_encodings()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


# ---------------------------------------------------------------------------
# Pipeline & Live Feed endpoints (Partition 3 - Dashboard)
# ---------------------------------------------------------------------------

@app.route('/api/pipeline/<scan_id>', methods=['GET'])
@_require_api_key
@_rate_limit
def get_pipeline(scan_id):
    """Return the real-time pipeline state for a scan."""
    scan_info = _active_scans.get(scan_id)
    if scan_info is None:
        return jsonify({'status': 'error', 'data': 'Scan not found'}), 404

    engine = scan_info.get('engine')
    if engine and hasattr(engine, 'get_pipeline_state'):
        pipeline = engine.get_pipeline_state()
    else:
        pipeline = scan_info.get('pipeline', {})

    return jsonify({'status': 'success', 'data': pipeline})


@app.route('/api/pipeline/<scan_id>/events', methods=['GET'])
@_require_api_key
@_rate_limit
def get_pipeline_events(scan_id):
    """Return pipeline events (optionally filtered by after_index)."""
    scan_info = _active_scans.get(scan_id)
    if scan_info is None:
        return jsonify({'status': 'error', 'data': 'Scan not found'}), 404

    engine = scan_info.get('engine')
    after = request.args.get('after', 0, type=int)

    events = []
    if engine and hasattr(engine, 'pipeline'):
        events = engine.pipeline.get('events', [])

    # Return only events after the given index for incremental polling
    filtered = events[after:]
    return jsonify({
        'status': 'success',
        'data': {
            'events': filtered,
            'total': len(events),
            'next_index': len(events),
        },
    })


@app.route('/api/exploit-results/<scan_id>', methods=['GET'])
@_require_api_key
@_rate_limit
def get_exploit_results(scan_id):
    """Return exploitation results from the attack router."""
    scan_info = _active_scans.get(scan_id)
    if scan_info is None:
        return jsonify({'status': 'error', 'data': 'Scan not found'}), 404

    engine = scan_info.get('engine')
    results = {
        'attack_routes': [],
        'post_exploit': [],
        'shells': [],
        'poc_data': [],
    }

    if engine:
        # Attack router results
        if hasattr(engine, 'attack_router') and engine.attack_router:
            state = engine.attack_router.get_pipeline_state()
            results['attack_routes'] = state.get('routes', [])

        # Post-exploitation results
        if hasattr(engine, 'post_exploit_results') and engine.post_exploit_results:
            if isinstance(engine.post_exploit_results, list):
                for r in engine.post_exploit_results:
                    if isinstance(r, dict):
                        results['post_exploit'].append(r)

    # Shells from database
    db = _get_db()
    if db:
        try:
            shells = db.get_shells()
            results['shells'] = [
                {
                    'shell_id': s.get('shell_id', ''),
                    'url': s.get('url', ''),
                    'shell_type': s.get('shell_type', ''),
                    'created_at': str(s.get('created_at', '')),
                }
                for s in shells
            ]
        except Exception:
            pass

    return jsonify({'status': 'success', 'data': results})


@app.route('/api/generate-poc/<scan_id>/<int:finding_index>', methods=['POST'])
@_require_api_key
@_rate_limit
def generate_poc(scan_id, finding_index):
    """Generate a POC for a specific finding."""
    scan_info = _active_scans.get(scan_id)
    if scan_info is None:
        return jsonify({'status': 'error', 'data': 'Scan not found'}), 404

    engine = scan_info.get('engine')
    if engine is None or not engine.findings:
        return jsonify({'status': 'error', 'data': 'No findings available'}), 400

    if finding_index < 0 or finding_index >= len(engine.findings):
        return jsonify({'status': 'error', 'data': 'Invalid finding index'}), 400

    try:
        from core.payload_generator import PayloadGenerator
        generator = PayloadGenerator()
        poc = generator.generate_poc(engine.findings[finding_index])
        return jsonify({'status': 'success', 'data': poc})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/attack-route/<scan_id>', methods=['POST'])
@_require_api_key
@_rate_limit
def trigger_attack_route(scan_id):
    """Manually trigger the attack router for a scan's findings."""
    scan_info = _active_scans.get(scan_id)
    if scan_info is None:
        return jsonify({'status': 'error', 'data': 'Scan not found'}), 404

    engine = scan_info.get('engine')
    if engine is None or not engine.findings:
        return jsonify({'status': 'error', 'data': 'No findings to route'}), 400

    try:
        from core.attack_router import AttackRouter
        router = AttackRouter(engine)
        routes = router.route(engine.findings)
        results = router.execute(routes)
        engine.attack_router = router
        return jsonify({
            'status': 'success',
            'data': {
                'routes_planned': len(routes),
                'results': results,
            },
        })
    except Exception as exc:
        logger.error('Attack router error: %s', exc)
        return jsonify({'status': 'error', 'data': str(exc)}), 500


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
        logger.info("Starting ATOMIC Dashboard on http://%s:%s", host, port)
        if _API_KEY:
            logger.info("API key authentication enabled")
        else:
            logger.warning("No ATOMIC_API_KEY set — API endpoints are open")
        logger.warning("FOR AUTHORIZED TESTING ONLY")
        app.run(host=host, port=port, debug=debug)

    return app, run_app


if __name__ == '__main__':
    _, runner = create_app(debug=os.environ.get('FLASK_DEBUG', '').lower() == '1')
    runner()
