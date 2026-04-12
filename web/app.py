#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Flask Web Dashboard
"""
import os
import json
import logging
import re
import subprocess
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps


from config import Config, Colors
from core.engine import AtomicEngine, Finding
from core.rules_engine import RulesEngine
from utils.database import Database, ScanModel, FindingModel, SQLALCHEMY_AVAILABLE

try:
    from flask import (
        Flask, render_template, request, jsonify, send_from_directory
    )
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False

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

# SocketIO for real-time updates (falls back to polling if unavailable)
socketio = None
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

_active_scans = {}
_scans_lock = threading.Lock()

# ---------------------------------------------------------------------------
# In-memory chat store for team collaboration on the dashboard
# ---------------------------------------------------------------------------
_chat_messages: list = []
_chat_lock = threading.Lock()
_CHAT_MAX_MESSAGES = 500  # keep last N messages in memory

# Scan-ID must be a hex UUID (no slashes, dots, or traversal chars).
_SAFE_SCAN_ID = re.compile(r'^[a-zA-Z0-9_-]+$')


# ---------------------------------------------------------------------------
# API-key authentication — REMOVED
# ---------------------------------------------------------------------------
# The API key gate has been removed so the scanner works without any key.
# The _require_api_key decorator is kept as a transparent pass-through for
# backward compatibility (any code that still references it will keep working).

# Read the optional API key (used only for startup logging in run_app()).
_API_KEY = os.environ.get('ATOMIC_API_KEY', '')

def _require_api_key(f):
    """No-op decorator kept for backward compatibility (key requirement removed)."""
    return f


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


def _validate_shell_id(shell_id: str) -> bool:
    """Validate shell_id format (alphanumeric, dashes, underscores only)."""
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', shell_id))


def _get_db():
    """Get a database instance."""
    if not SQLALCHEMY_AVAILABLE:
        return None
    try:
        return Database()
    except Exception:
        return None


def _emit_ws(event, data):
    """Emit a WebSocket event to all connected clients (no-op if SocketIO unavailable)."""
    if socketio is not None:
        try:
            socketio.emit(event, data, namespace='/')
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Module-level component instances (lazy-safe — import errors are caught)
# ---------------------------------------------------------------------------
try:
    from core.auth import UserStore, PERMISSIONS, ROLES
    _user_store = UserStore()
except Exception:
    logger.debug('core.auth unavailable — auth endpoints disabled')
    _user_store = None
    PERMISSIONS = {}
    ROLES = ()

try:
    from core.scheduler import ScanScheduler
    _scheduler = ScanScheduler()
except Exception:
    logger.debug('core.scheduler unavailable — scheduler endpoints disabled')
    _scheduler = None

try:
    from core.audit_logger import AuditLogger
    _audit_logger = AuditLogger()
except Exception:
    logger.debug('core.audit_logger unavailable — audit endpoints disabled')
    _audit_logger = None

try:
    from core.plugin_system import PluginManager
    _plugin_manager = PluginManager()
except Exception:
    logger.debug('core.plugin_system unavailable — plugin endpoints disabled')
    _plugin_manager = None

try:
    from core.notification import NotificationManager
    _notification_manager = NotificationManager()
except Exception:
    logger.debug('core.notification unavailable — notification endpoints disabled')
    _notification_manager = None

try:
    from core.ai_engine import AIEngine
    _AI_ENGINE_AVAILABLE = True
except Exception:
    logger.debug('core.ai_engine unavailable — AI endpoints disabled')
    _AI_ENGINE_AVAILABLE = False

# Ollama conversation history (per-session, in-memory)
_ollama_chat_history: list = []
_ollama_lock = threading.Lock()
_OLLAMA_MAX_HISTORY = 100
_OLLAMA_CONTEXT_MESSAGES = 20  # number of recent exchanges to include as context


def _get_current_user():
    """Extract the authenticated user from Bearer token or API key header."""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer ') and _user_store is not None:
        token = auth[7:]
        payload = _user_store.validate_request_token(token)
        if payload:
            return payload
    api_key = request.headers.get('X-API-Key', '')
    if api_key and _user_store is not None:
        user = _user_store.authenticate_api_key(api_key)
        if user:
            return {'sub': user.username, 'role': user.role}
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
    _emit_ws('scan_started', {'scan_id': scan_id, 'target': target})
    try:
        engine = AtomicEngine(config)
        engine.scan_id = scan_id
        # Attach a live-event callback so the engine pushes events to SocketIO
        engine._ws_callback = lambda evt, d: _emit_ws(evt, {**d, 'scan_id': scan_id})
        with _scans_lock:
            _active_scans[scan_id]['engine'] = engine
        engine.scan(target)
        engine.generate_reports()
        with _scans_lock:
            _active_scans[scan_id]['status'] = 'completed'
            _active_scans[scan_id]['findings'] = len(engine.findings)
            _active_scans[scan_id]['end_time'] = datetime.now(timezone.utc).isoformat()
            _active_scans[scan_id]['pipeline'] = engine.get_pipeline_state()
        _emit_ws('scan_completed', {
            'scan_id': scan_id,
            'findings': len(engine.findings),
        })
    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        with _scans_lock:
            _active_scans[scan_id]['status'] = 'failed'
            _active_scans[scan_id]['error'] = str(exc)
            _active_scans[scan_id]['end_time'] = datetime.now(timezone.utc).isoformat()
        _emit_ws('scan_failed', {'scan_id': scan_id})


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
        'exploit_search': body.get('exploit_search', False) or full_scan,
        'attack_map': body.get('attack_map', False) or full_scan,
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
    """Return the current status of a scan including pipeline state.

    For active scans the response includes real-time pipeline data from the
    engine (phase, events, attack routes).  The internal ``engine`` reference
    is never serialised into the JSON response.
    """
    with _scans_lock:
        scan_data = _active_scans.get(scan_id)
        if scan_data is not None:
            info = dict(scan_data)
        else:
            info = None
    if info is not None:
        # Add live pipeline data from engine (exclude engine object from JSON)
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
                'password': s.get('password', 'cmd'),
            })
        return jsonify({'status': 'success', 'data': data})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Failed to list shells'}), 500


@app.route('/api/shell/<shell_id>/execute', methods=['POST'])
@_require_api_key
@_rate_limit
def execute_shell_command(shell_id):
    """Execute a command on a deployed shell.

    Expects JSON body: {"command": "ls -la"}
    Returns the command output.
    """
    body = request.get_json(silent=True) or {}
    cmd = body.get('command', '').strip()
    if not cmd:
        return jsonify({'status': 'error', 'data': 'No command provided'}), 400

    # Validate shell_id format (alphanumeric + dashes only)
    if not _validate_shell_id(shell_id):
        return jsonify({'status': 'error', 'data': 'Invalid shell ID'}), 400

    try:
        from modules.shell.manager import ShellManager
        manager = ShellManager()
        result = manager.execute_command(shell_id, cmd)
        # Sanitize output: strip ANSI color codes and limit length
        clean_result = re.sub(r'\x1b\[[0-9;]*m', '', result) if result else ''
        _emit_ws('shell_command', {
            'shell_id': shell_id,
            'command': cmd,
            'output_length': len(clean_result),
        })
        return jsonify({'status': 'success', 'data': {'output': clean_result[:50000]}})
    except Exception as exc:
        logger.error('Shell execute error: %s', exc)
        return jsonify({'status': 'error', 'data': 'Command execution failed'}), 500


@app.route('/api/shell/<shell_id>/info', methods=['GET'])
@_require_api_key
@_rate_limit
def shell_info(shell_id):
    """Return details for a specific shell."""
    if not _validate_shell_id(shell_id):
        return jsonify({'status': 'error', 'data': 'Invalid shell ID'}), 400

    db = _get_db()
    if db is None:
        return jsonify({'status': 'error', 'data': 'Database unavailable'}), 500

    try:
        shells = db.get_shells()
        for s in shells:
            if s.get('shell_id', '') == shell_id:
                return jsonify({
                    'status': 'success',
                    'data': {
                        'shell_id': s.get('shell_id', ''),
                        'url': s.get('url', ''),
                        'shell_type': s.get('shell_type', ''),
                        'created_at': str(s.get('created_at', '')),
                        'last_used': str(s.get('last_used', '')),
                        'password': s.get('password', 'cmd'),
                    },
                })
        return jsonify({'status': 'error', 'data': 'Shell not found'}), 404
    except Exception:
        return jsonify({'status': 'error', 'data': 'Failed to get shell info'}), 500


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
        logger.error('POC generation error: %s', exc)
        return jsonify({'status': 'error', 'data': 'POC generation failed'}), 500


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
        return jsonify({'status': 'error', 'data': 'Attack routing failed'}), 500


# ---------------------------------------------------------------------------
# Exploit Intelligence & Attack Map API endpoints (Phase 9B + Phase 11)
# ---------------------------------------------------------------------------

def _serialize_exploit_record(rec):
    """Safely serialize an ExploitRecord (dataclass or dict) to JSON-safe dict."""
    if rec is None:
        return None
    if isinstance(rec, dict):
        return rec
    result = {}
    for field_name in (
        'finding_id', 'cve_id', 'exploit_maturity', 'availability',
        'actively_exploited', 'metasploit_module', 'metasploit_rank',
        'nuclei_template', 'exploitdb_id', 'exploitdb_verified',
        'packetstorm_url', 'cvss_score', 'cvss_vector',
        'patch_available', 'patch_url',
    ):
        result[field_name] = getattr(rec, field_name, None)
    # Lists
    for list_field in ('cwe_ids', 'affected_versions', 'references'):
        val = getattr(rec, list_field, None)
        result[list_field] = list(val) if val else []
    # GitHub PoCs
    pocs = getattr(rec, 'github_pocs', None)
    if pocs:
        result['github_pocs'] = []
        for p in pocs:
            if isinstance(p, dict):
                result['github_pocs'].append(p)
            else:
                result['github_pocs'].append({
                    'repo_url': getattr(p, 'repo_url', ''),
                    'stars': getattr(p, 'stars', 0),
                    'description': getattr(p, 'description', ''),
                    'language': getattr(p, 'language', ''),
                    'last_commit': getattr(p, 'last_commit', ''),
                })
    else:
        result['github_pocs'] = []
    # CISA KEV
    kev = getattr(rec, 'cisa_kev', None)
    if kev:
        if isinstance(kev, dict):
            result['cisa_kev'] = kev
        else:
            result['cisa_kev'] = {
                'vendor_project': getattr(kev, 'vendor_project', ''),
                'product': getattr(kev, 'product', ''),
                'vulnerability_name': getattr(kev, 'vulnerability_name', ''),
                'date_added': getattr(kev, 'date_added', ''),
                'required_action': getattr(kev, 'required_action', ''),
                'due_date': getattr(kev, 'due_date', ''),
            }
    else:
        result['cisa_kev'] = None
    return result


@app.route('/api/exploit-intel/<scan_id>', methods=['GET'])
@_require_api_key
@_rate_limit
def get_exploit_intel(scan_id):
    """Return exploit enrichment data for a scan's findings (Phase 9B)."""
    if not _SAFE_SCAN_ID.match(scan_id):
        return jsonify({'status': 'error', 'data': 'Invalid scan ID'}), 400

    scan_info = _active_scans.get(scan_id)
    if scan_info is None:
        return jsonify({'status': 'error', 'data': 'Scan not found'}), 404

    engine = scan_info.get('engine')
    if engine is None or not engine.findings:
        return jsonify({'status': 'success', 'data': {
            'findings': [], 'summary': {
                'total': 0, 'weaponized': 0, 'public_poc': 0,
                'partial_poc': 0, 'theoretical': 0,
                'actively_exploited': 0, 'msf_ready': 0, 'nuclei_ready': 0,
            }
        }})

    enriched = []
    summary = {
        'total': 0, 'weaponized': 0, 'public_poc': 0,
        'partial_poc': 0, 'theoretical': 0,
        'actively_exploited': 0, 'msf_ready': 0, 'nuclei_ready': 0,
    }

    for f in engine.findings:
        entry = {
            'technique': getattr(f, 'technique', ''),
            'severity': getattr(f, 'severity', 'INFO'),
            'url': getattr(f, 'url', ''),
            'param': getattr(f, 'param', ''),
            'cvss': getattr(f, 'cvss', 0.0),
        }

        # Phase 9B enrichment fields
        exploit_rec = getattr(f, 'exploit_record', None)
        entry['exploit_record'] = _serialize_exploit_record(exploit_rec)
        entry['exploit_availability'] = getattr(f, 'exploit_availability', 'THEORETICAL')
        entry['actively_exploited'] = getattr(f, 'actively_exploited', False)
        entry['adjusted_cvss'] = getattr(f, 'adjusted_cvss', getattr(f, 'cvss', 0.0))
        entry['adjusted_severity'] = getattr(f, 'adjusted_severity', getattr(f, 'severity', 'INFO'))
        entry['metasploit_ready'] = getattr(f, 'metasploit_ready', False)
        entry['nuclei_ready'] = getattr(f, 'nuclei_ready', False)
        entry['final_priority'] = getattr(f, 'final_priority', 0.0)

        # Summary counters
        summary['total'] += 1
        avail = entry['exploit_availability']
        if avail == 'WEAPONIZED':
            summary['weaponized'] += 1
        elif avail == 'PUBLIC_POC':
            summary['public_poc'] += 1
        elif avail == 'PARTIAL_POC':
            summary['partial_poc'] += 1
        else:
            summary['theoretical'] += 1
        if entry['actively_exploited']:
            summary['actively_exploited'] += 1
        if entry['metasploit_ready']:
            summary['msf_ready'] += 1
        if entry['nuclei_ready']:
            summary['nuclei_ready'] += 1

        enriched.append(entry)

    return jsonify({'status': 'success', 'data': {
        'findings': enriched,
        'summary': summary,
    }})


@app.route('/api/attack-map/<scan_id>', methods=['GET'])
@_require_api_key
@_rate_limit
def get_attack_map(scan_id):
    """Return the exploit-aware attack map for a scan (Phase 11)."""
    if not _SAFE_SCAN_ID.match(scan_id):
        return jsonify({'status': 'error', 'data': 'Invalid scan ID'}), 400

    scan_info = _active_scans.get(scan_id)
    if scan_info is None:
        return jsonify({'status': 'error', 'data': 'Scan not found'}), 404

    engine = scan_info.get('engine')
    attack_map = getattr(engine, '_attack_map', None) if engine else None

    if not attack_map:
        return jsonify({'status': 'success', 'data': {
            'nodes': [], 'edges': [], 'paths': [],
            'impact_zones': [], 'simulation': {},
            'summary': {
                'total_nodes': 0, 'entry_points': 0, 'weaponized_entries': 0,
                'critical_paths': 0, 'zero_click_paths': 0, 'msf_ready_paths': 0,
                'cisa_kev_in_map': False, 'impact_zones_active': [],
                'highest_path_score': 0.0, 'exploit_coverage_pct': 0.0,
                'fastest_compromise': {}, 'most_damaging': {},
            },
        }})

    # Serialize nodes
    nodes = []
    for n in attack_map.get('nodes', []):
        if isinstance(n, dict):
            nodes.append(n)
        else:
            nodes.append({
                'id': getattr(n, 'id', ''),
                'finding_id': getattr(n, 'finding_id', ''),
                'label': getattr(n, 'label', ''),
                'type': getattr(n, 'type', ''),
                'severity': getattr(n, 'severity', 'INFO'),
                'cvss': getattr(n, 'cvss', 0.0),
                'adjusted_cvss': getattr(n, 'adjusted_cvss', 0.0),
                'vuln_class': getattr(n, 'vuln_class', ''),
                'endpoint': getattr(n, 'endpoint', ''),
                'exploit_availability': getattr(n, 'exploit_availability', 'THEORETICAL'),
                'actively_exploited': getattr(n, 'actively_exploited', False),
                'metasploit_ready': getattr(n, 'metasploit_ready', False),
                'nuclei_ready': getattr(n, 'nuclei_ready', False),
                'exploitdb_id': getattr(n, 'exploitdb_id', None),
                'cisa_kev': getattr(n, 'cisa_kev', False),
            })

    # Serialize edges
    edges = []
    for e in attack_map.get('edges', []):
        if isinstance(e, dict):
            edges.append(e)
        else:
            edges.append({
                'from': getattr(e, 'from_node', getattr(e, 'from_id', '')),
                'to': getattr(e, 'to_node', getattr(e, 'to_id', '')),
                'type': getattr(e, 'type', ''),
                'confidence': getattr(e, 'confidence', 0.0),
                'exploit_assisted': getattr(e, 'exploit_assisted', False),
            })

    # Serialize paths
    paths = []
    for p in attack_map.get('paths', []):
        if isinstance(p, dict):
            paths.append(p)
        else:
            paths.append({
                'id': getattr(p, 'id', ''),
                'classification': getattr(p, 'classification', []),
                'nodes': getattr(p, 'nodes', []),
                'path_score': getattr(p, 'path_score', 0.0),
                'entry': getattr(p, 'entry', ''),
                'impact': getattr(p, 'impact', getattr(p, 'final_impact', '')),
                'narrative': getattr(p, 'narrative', ''),
                'steps': getattr(p, 'steps', []),
                'auth_required': getattr(p, 'auth_required', False),
                'fully_weaponized': getattr(p, 'fully_weaponized', False),
                'msf_end_to_end': getattr(p, 'msf_end_to_end', False),
                'nuclei_end_to_end': getattr(p, 'nuclei_end_to_end', False),
                'cisa_kev_in_path': getattr(p, 'cisa_kev_in_path', False),
                'steps_required': getattr(p, 'steps_required', 0),
            })

    # Serialize impact zones
    impact_zones = []
    for z in attack_map.get('impact_zones', []):
        if isinstance(z, dict):
            impact_zones.append(z)
        else:
            impact_zones.append({
                'zone': getattr(z, 'zone', ''),
                'triggered_by': getattr(z, 'triggered_by', []),
                'assets_at_risk': getattr(z, 'assets_at_risk', []),
                'likelihood': getattr(z, 'likelihood', ''),
                'weaponized_path_exists': getattr(z, 'weaponized_path_exists', False),
            })

    # Serialize simulation
    simulation = attack_map.get('simulation', {})
    if not isinstance(simulation, dict):
        simulation = {}

    # Summary
    summary = attack_map.get('summary', {})
    if not isinstance(summary, dict):
        summary = {}

    return jsonify({'status': 'success', 'data': {
        'nodes': nodes,
        'edges': edges,
        'paths': paths,
        'impact_zones': impact_zones,
        'simulation': simulation,
        'summary': summary,
    }})


# ---------------------------------------------------------------------------
# Scanner Rules API endpoints
# ---------------------------------------------------------------------------

# Shared rules engine instance (lazy-initialized)
_rules_engine = None
_rules_lock = threading.Lock()


def _get_rules_engine():
    """Return the shared RulesEngine instance, creating it on first access."""
    global _rules_engine
    if _rules_engine is None:
        with _rules_lock:
            if _rules_engine is None:
                _rules_engine = RulesEngine()
    return _rules_engine


@app.route('/api/rules', methods=['GET'])
@_require_api_key
@_rate_limit
def get_scanner_rules():
    """Return the full scanner rules configuration."""
    try:
        rules = _get_rules_engine()
        return jsonify({'status': 'success', 'data': rules.to_dict()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/rules/profile', methods=['GET'])
@_require_api_key
@_rate_limit
def get_rules_profile():
    """Return the active profile name and pipeline stages."""
    try:
        rules = _get_rules_engine()
        return jsonify({
            'status': 'success',
            'data': {
                'profile': rules.profile,
                'pipeline_stages': rules.pipeline_stages,
            },
        })
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/rules/runtime', methods=['GET'])
@_require_api_key
@_rate_limit
def get_rules_runtime():
    """Return runtime defaults from scanner rules."""
    try:
        rules = _get_rules_engine()
        return jsonify({'status': 'success', 'data': rules.runtime})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/rules/scoring', methods=['GET'])
@_require_api_key
@_rate_limit
def get_rules_scoring():
    """Return scoring configuration."""
    try:
        rules = _get_rules_engine()
        return jsonify({'status': 'success', 'data': rules.scoring})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/rules/vulnmap', methods=['GET'])
@_require_api_key
@_rate_limit
def get_rules_vulnmap():
    """Return the vulnerability map configuration."""
    try:
        rules = _get_rules_engine()
        return jsonify({'status': 'success', 'data': rules.vuln_map})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/rules/vulnmap/<vuln_type>', methods=['GET'])
@_require_api_key
@_rate_limit
def get_rules_vuln_config(vuln_type):
    """Return configuration for a specific vulnerability type."""
    try:
        rules = _get_rules_engine()
        cfg = rules.get_vuln_config(vuln_type)
        if not cfg:
            return jsonify({'status': 'error', 'data': f'Unknown vulnerability type: {vuln_type}'}), 404
        return jsonify({'status': 'success', 'data': cfg})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/rules/verification', methods=['GET'])
@_require_api_key
@_rate_limit
def get_rules_verification():
    """Return verification configuration."""
    try:
        rules = _get_rules_engine()
        return jsonify({'status': 'success', 'data': rules.verification})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/rules/baseline', methods=['GET'])
@_require_api_key
@_rate_limit
def get_rules_baseline():
    """Return baseline configuration."""
    try:
        rules = _get_rules_engine()
        return jsonify({'status': 'success', 'data': rules.baseline})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/rules/reporting', methods=['GET'])
@_require_api_key
@_rate_limit
def get_rules_reporting():
    """Return reporting configuration."""
    try:
        rules = _get_rules_engine()
        return jsonify({'status': 'success', 'data': rules.reporting})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


@app.route('/api/rules/reload', methods=['POST'])
@_require_api_key
@_rate_limit
def reload_scanner_rules():
    """Reload scanner rules from the YAML file."""
    global _rules_engine
    try:
        with _rules_lock:
            _rules_engine = RulesEngine()
        return jsonify({'status': 'success', 'data': 'Rules reloaded'})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': str(exc)}), 500


# ---------------------------------------------------------------------------
# Authentication & User Management API
# ---------------------------------------------------------------------------

@app.route('/api/auth/login', methods=['POST'])
@_rate_limit
def auth_login():
    """Authenticate user and return JWT tokens."""
    if _user_store is None:
        return jsonify({'status': 'error', 'data': 'Auth module unavailable'}), 503
    body = request.get_json(silent=True)
    if not body or not body.get('username') or not body.get('password'):
        return jsonify({'status': 'error', 'data': 'Missing username or password'}), 400
    try:
        result = _user_store.authenticate(body['username'], body['password'])
        if not result:
            return jsonify({'status': 'error', 'data': 'Invalid credentials'}), 401
        return jsonify({'status': 'success', 'data': result})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Authentication error'}), 500


@app.route('/api/auth/refresh', methods=['POST'])
@_rate_limit
def auth_refresh():
    """Refresh an access token using a refresh token."""
    if _user_store is None:
        return jsonify({'status': 'error', 'data': 'Auth module unavailable'}), 503
    body = request.get_json(silent=True)
    if not body or not body.get('refresh_token'):
        return jsonify({'status': 'error', 'data': 'Missing refresh_token'}), 400
    try:
        result = _user_store.refresh_access_token(body['refresh_token'])
        if not result:
            return jsonify({'status': 'error', 'data': 'Invalid or expired refresh token'}), 401
        return jsonify({'status': 'success', 'data': result})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Authentication error'}), 500


@app.route('/api/auth/me', methods=['GET'])
@_require_api_key
@_rate_limit
def auth_me():
    """Get current user info from the Bearer token."""
    user = _get_current_user()
    if not user:
        return jsonify({'status': 'error', 'data': 'Authentication required'}), 401
    try:
        info = _user_store.get_user(user['sub'])
        if not info:
            return jsonify({'status': 'error', 'data': 'User not found'}), 404
        return jsonify({'status': 'success', 'data': {
            'username': info.username,
            'role': info.role,
            'is_active': info.is_active,
            'created_at': info.created_at,
            'last_login': info.last_login,
        }})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Authentication error'}), 500


@app.route('/api/auth/users', methods=['POST'])
@_require_api_key
@_rate_limit
def auth_create_user():
    """Create a new user (admin only)."""
    caller = _get_current_user()
    if not caller or caller.get('role') != 'admin':
        return jsonify({'status': 'error', 'data': 'Admin access required'}), 403
    body = request.get_json(silent=True)
    if not body or not body.get('username') or not body.get('password'):
        return jsonify({'status': 'error', 'data': 'Missing username or password'}), 400
    role = body.get('role', 'viewer')
    if role not in ROLES:
        return jsonify({'status': 'error', 'data': f'Invalid role. Must be one of: {ROLES}'}), 400
    try:
        user = _user_store.create_user(body['username'], body['password'], role)
        if not user:
            return jsonify({'status': 'error', 'data': 'User creation failed (duplicate or invalid)'}), 409
        return jsonify({'status': 'success', 'data': {
            'username': user.username, 'role': user.role,
        }}), 201
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Authentication error'}), 500


@app.route('/api/auth/users', methods=['GET'])
@_require_api_key
@_rate_limit
def auth_list_users():
    """List all users (admin only)."""
    caller = _get_current_user()
    if not caller or caller.get('role') != 'admin':
        return jsonify({'status': 'error', 'data': 'Admin access required'}), 403
    try:
        return jsonify({'status': 'success', 'data': _user_store.list_users()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Authentication error'}), 500


@app.route('/api/auth/users/<username>/role', methods=['PUT'])
@_require_api_key
@_rate_limit
def auth_update_role(username):
    """Update a user's role (admin only)."""
    caller = _get_current_user()
    if not caller or caller.get('role') != 'admin':
        return jsonify({'status': 'error', 'data': 'Admin access required'}), 403
    body = request.get_json(silent=True)
    if not body or not body.get('role'):
        return jsonify({'status': 'error', 'data': 'Missing role'}), 400
    try:
        if _user_store.update_user_role(username, body['role']):
            return jsonify({'status': 'success', 'data': 'Role updated'})
        return jsonify({'status': 'error', 'data': 'User not found or invalid role'}), 404
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Authentication error'}), 500


@app.route('/api/auth/users/<username>', methods=['DELETE'])
@_require_api_key
@_rate_limit
def auth_delete_user(username):
    """Delete a user (admin only)."""
    caller = _get_current_user()
    if not caller or caller.get('role') != 'admin':
        return jsonify({'status': 'error', 'data': 'Admin access required'}), 403
    try:
        if _user_store.delete_user(username):
            return jsonify({'status': 'success', 'data': 'User deleted'})
        return jsonify({'status': 'error', 'data': 'User not found'}), 404
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Authentication error'}), 500


@app.route('/api/auth/api-key', methods=['POST'])
@_require_api_key
@_rate_limit
def auth_generate_api_key():
    """Generate a new API key for the authenticated user (analyst+)."""
    caller = _get_current_user()
    if not caller or caller.get('role') not in ('admin', 'analyst'):
        return jsonify({'status': 'error', 'data': 'Analyst or admin access required'}), 403
    try:
        key = _user_store.generate_user_api_key(caller['sub'])
        if not key:
            return jsonify({'status': 'error', 'data': 'Key generation failed'}), 500
        return jsonify({'status': 'success', 'data': {'api_key': key}})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Authentication error'}), 500


# ---------------------------------------------------------------------------
# Scheduled Scanning API
# ---------------------------------------------------------------------------

@app.route('/api/schedules', methods=['GET'])
@_require_api_key
@_rate_limit
def list_schedules():
    """List all scheduled scans."""
    if _scheduler is None:
        return jsonify({'status': 'error', 'data': 'Scheduler unavailable'}), 503
    try:
        return jsonify({'status': 'success', 'data': _scheduler.list_schedules()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Scheduler operation failed'}), 500


@app.route('/api/schedules', methods=['POST'])
@_require_api_key
@_rate_limit
def create_schedule():
    """Create a new scheduled scan."""
    if _scheduler is None:
        return jsonify({'status': 'error', 'data': 'Scheduler unavailable'}), 503
    body = request.get_json(silent=True)
    if not body or not body.get('name') or not body.get('target'):
        return jsonify({'status': 'error', 'data': 'Missing name or target'}), 400
    try:
        entry = _scheduler.add_schedule(
            name=body['name'],
            target=body['target'],
            schedule_type=body.get('schedule_type', 'interval'),
            interval_seconds=body.get('interval_seconds', 3600),
            cron_expression=body.get('cron_expression', ''),
            max_runs=body.get('max_runs', 0),
            config=body.get('config'),
            created_by=body.get('created_by', ''),
        )
        return jsonify({'status': 'success', 'data': entry.to_dict()}), 201
    except (ValueError, TypeError) as exc:
        return jsonify({'status': 'error', 'data': 'Scheduler operation failed'}), 400
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Scheduler operation failed'}), 500


@app.route('/api/schedules/<schedule_id>', methods=['GET'])
@_require_api_key
@_rate_limit
def get_schedule(schedule_id):
    """Get details of a specific schedule."""
    if _scheduler is None:
        return jsonify({'status': 'error', 'data': 'Scheduler unavailable'}), 503
    if not _SAFE_SCAN_ID.match(schedule_id):
        return jsonify({'status': 'error', 'data': 'Invalid schedule ID'}), 400
    try:
        entry = _scheduler.get_schedule(schedule_id)
        if not entry:
            return jsonify({'status': 'error', 'data': 'Schedule not found'}), 404
        return jsonify({'status': 'success', 'data': entry.to_dict()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Scheduler operation failed'}), 500


@app.route('/api/schedules/<schedule_id>', methods=['DELETE'])
@_require_api_key
@_rate_limit
def delete_schedule(schedule_id):
    """Remove a scheduled scan."""
    if _scheduler is None:
        return jsonify({'status': 'error', 'data': 'Scheduler unavailable'}), 503
    if not _SAFE_SCAN_ID.match(schedule_id):
        return jsonify({'status': 'error', 'data': 'Invalid schedule ID'}), 400
    try:
        if _scheduler.remove_schedule(schedule_id):
            return jsonify({'status': 'success', 'data': 'Schedule removed'})
        return jsonify({'status': 'error', 'data': 'Schedule not found'}), 404
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Scheduler operation failed'}), 500


@app.route('/api/schedules/<schedule_id>/toggle', methods=['PUT'])
@_require_api_key
@_rate_limit
def toggle_schedule(schedule_id):
    """Enable or disable a scheduled scan."""
    if _scheduler is None:
        return jsonify({'status': 'error', 'data': 'Scheduler unavailable'}), 503
    if not _SAFE_SCAN_ID.match(schedule_id):
        return jsonify({'status': 'error', 'data': 'Invalid schedule ID'}), 400
    body = request.get_json(silent=True)
    enabled = body.get('enabled', True) if body else True
    try:
        if _scheduler.toggle_schedule(schedule_id, enabled):
            return jsonify({'status': 'success', 'data': f'Schedule {"enabled" if enabled else "disabled"}'})
        return jsonify({'status': 'error', 'data': 'Schedule not found'}), 404
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Scheduler operation failed'}), 500


@app.route('/api/schedules/history', methods=['GET'])
@_require_api_key
@_rate_limit
def get_schedule_history():
    """Get execution history for scheduled scans."""
    if _scheduler is None:
        return jsonify({'status': 'error', 'data': 'Scheduler unavailable'}), 503
    try:
        limit = request.args.get('limit', 50, type=int)
        return jsonify({'status': 'success', 'data': _scheduler.get_history(limit=limit)})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Scheduler operation failed'}), 500


@app.route('/api/scheduler/start', methods=['POST'])
@_require_api_key
@_rate_limit
def start_scheduler():
    """Start the background scheduler."""
    if _scheduler is None:
        return jsonify({'status': 'error', 'data': 'Scheduler unavailable'}), 503
    try:
        _scheduler.start()
        return jsonify({'status': 'success', 'data': 'Scheduler started'})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Scheduler operation failed'}), 500


@app.route('/api/scheduler/stop', methods=['POST'])
@_require_api_key
@_rate_limit
def stop_scheduler():
    """Stop the background scheduler."""
    if _scheduler is None:
        return jsonify({'status': 'error', 'data': 'Scheduler unavailable'}), 503
    try:
        _scheduler.stop()
        return jsonify({'status': 'success', 'data': 'Scheduler stopped'})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Scheduler operation failed'}), 500


# ---------------------------------------------------------------------------
# Compliance Mapping API
# ---------------------------------------------------------------------------

@app.route('/api/compliance/<scan_id>', methods=['POST'])
@_require_api_key
@_rate_limit
def run_compliance_analysis(scan_id):
    """Run compliance analysis on a scan's findings."""
    if not _SAFE_SCAN_ID.match(scan_id):
        return jsonify({'status': 'error', 'data': 'Invalid scan ID'}), 400
    body = request.get_json(silent=True)
    frameworks = body.get('frameworks') if body else None
    try:
        from core.compliance import ComplianceEngine
        engine = ComplianceEngine()
        # Gather findings from in-memory active scans or database
        findings = []
        with _scans_lock:
            scan_info = _active_scans.get(scan_id)
            if scan_info and scan_info.get('engine'):
                findings = scan_info['engine'].findings
        if not findings:
            db = _get_db()
            if db is not None:
                session = db.Session()
                try:
                    rows = session.query(FindingModel).filter_by(scan_id=scan_id).all()
                    findings = [
                        Finding(
                            technique=r.technique, severity=r.severity,
                            url=r.url, details=r.details,
                        ) for r in rows
                    ]
                finally:
                    session.close()
        report = engine.analyze(findings, scan_id=scan_id, frameworks=frameworks)
        return jsonify({'status': 'success', 'data': report.to_dict()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Internal server error'}), 500


@app.route('/api/compliance/frameworks', methods=['GET'])
@_require_api_key
@_rate_limit
def list_compliance_frameworks():
    """List available compliance frameworks."""
    try:
        from core.compliance import ComplianceEngine
        engine = ComplianceEngine()
        frameworks = [
            {'id': fw_id, 'controls': len(controls)}
            for fw_id, controls in engine.FRAMEWORKS.items()
        ]
        return jsonify({'status': 'success', 'data': frameworks})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Compliance analysis failed'}), 500


# ---------------------------------------------------------------------------
# Audit Log API
# ---------------------------------------------------------------------------

@app.route('/api/audit', methods=['GET'])
@_require_api_key
@_rate_limit
def get_audit_entries():
    """Get audit log entries with optional filters."""
    if _audit_logger is None:
        return jsonify({'status': 'error', 'data': 'Audit logger unavailable'}), 503
    try:
        entries = _audit_logger.get_entries(
            category=request.args.get('category'),
            actor=request.args.get('actor'),
            severity=request.args.get('severity'),
            limit=request.args.get('limit', 100, type=int),
        )
        return jsonify({'status': 'success', 'data': entries})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Audit query failed'}), 500


@app.route('/api/audit/stats', methods=['GET'])
@_require_api_key
@_rate_limit
def get_audit_stats():
    """Get audit log statistics."""
    if _audit_logger is None:
        return jsonify({'status': 'error', 'data': 'Audit logger unavailable'}), 503
    try:
        return jsonify({'status': 'success', 'data': _audit_logger.get_stats()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Audit query failed'}), 500


# ---------------------------------------------------------------------------
# External Tool Integration API
# ---------------------------------------------------------------------------

@app.route('/api/tools/external', methods=['GET'])
@_require_api_key
@_rate_limit
def list_external_tools():
    """List available external security tools and their status."""
    try:
        from core.tool_integrator import ToolIntegrator
        integrator = ToolIntegrator()
        return jsonify({'status': 'success', 'data': integrator.get_available_tools()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Tool execution failed'}), 500


@app.route('/api/tools/external/<tool_name>/run', methods=['POST'])
@_require_api_key
@_rate_limit
def run_external_tool(tool_name):
    """Run a specific external security tool against a target."""
    body = request.get_json(silent=True)
    if not body or not body.get('target'):
        return jsonify({'status': 'error', 'data': 'Missing target'}), 400
    try:
        from core.tool_integrator import ToolIntegrator
        integrator = ToolIntegrator()
        available = integrator.get_available_tools()
        if tool_name not in available:
            return jsonify({'status': 'error', 'data': f'Unknown tool: {tool_name}'}), 404
        if not available[tool_name]:
            return jsonify({'status': 'error', 'data': f'Tool {tool_name} is not installed'}), 503
        params = {k: v for k, v in body.items() if k != 'target'}
        result = integrator.run_tool(tool_name, body['target'], **params)
        return jsonify({'status': 'success', 'data': result.to_dict()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Tool execution failed'}), 500


# ---------------------------------------------------------------------------
# Recon Arsenal API — Advanced Discovery & Gathering Tools
# ---------------------------------------------------------------------------

@app.route('/api/recon/arsenal', methods=['GET'])
@_require_api_key
@_rate_limit
def list_recon_arsenal():
    """List all recon arsenal tools, their categories, and availability."""
    try:
        from core.recon_arsenal import ReconArsenal
        arsenal = ReconArsenal()
        return jsonify({
            'status': 'success',
            'data': {
                'tools': arsenal.get_all_tool_info(),
                'categories': arsenal.get_tools_by_category(),
                'available': arsenal.get_available_tools(),
            },
        })
    except Exception:
        return jsonify({'status': 'error', 'data': 'Recon arsenal unavailable'}), 500


@app.route('/api/recon/arsenal/<tool_name>/run', methods=['POST'])
@_require_api_key
@_rate_limit
def run_recon_tool(tool_name):
    """Run a specific recon arsenal tool against a target."""
    body = request.get_json(silent=True)
    if not body or not body.get('target'):
        return jsonify({'status': 'error', 'data': 'Missing target'}), 400
    try:
        from core.recon_arsenal import ReconArsenal
        arsenal = ReconArsenal()
        available = arsenal.get_available_tools()
        if tool_name not in available:
            return jsonify({'status': 'error', 'data': f'Unknown recon tool: {tool_name}'}), 404
        if not available[tool_name]:
            return jsonify({'status': 'error', 'data': f'Tool {tool_name} is not installed'}), 503
        params = {k: v for k, v in body.items() if k != 'target'}
        result = arsenal.run_tool(tool_name, body['target'], **params)
        return jsonify({'status': 'success', 'data': result.to_dict()})
    except Exception:
        return jsonify({'status': 'error', 'data': 'Recon tool execution failed'}), 500


@app.route('/api/recon/arsenal/full', methods=['POST'])
@_require_api_key
@_rate_limit
def run_full_recon():
    """Run full recon arsenal with all available tools."""
    body = request.get_json(silent=True)
    if not body or not body.get('target'):
        return jsonify({'status': 'error', 'data': 'Missing target'}), 400
    try:
        from core.recon_arsenal import ReconArsenal
        arsenal = ReconArsenal()
        domain = body.get('domain', '')
        results = arsenal.run_full_recon(body['target'], domain=domain)
        return jsonify({
            'status': 'success',
            'data': {
                name: res.to_dict() for name, res in results.items()
            },
        })
    except Exception:
        return jsonify({'status': 'error', 'data': 'Full recon failed'}), 500


# ---------------------------------------------------------------------------
# Plugin Management API
# ---------------------------------------------------------------------------

@app.route('/api/plugins', methods=['GET'])
@_require_api_key
@_rate_limit
def list_plugins():
    """List all registered plugins."""
    if _plugin_manager is None:
        return jsonify({'status': 'error', 'data': 'Plugin system unavailable'}), 503
    try:
        return jsonify({'status': 'success', 'data': _plugin_manager.list_plugins()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Plugin operation failed'}), 500


@app.route('/api/plugins/discover', methods=['POST'])
@_require_api_key
@_rate_limit
def discover_plugins():
    """Discover and load available plugins."""
    if _plugin_manager is None:
        return jsonify({'status': 'error', 'data': 'Plugin system unavailable'}), 503
    try:
        found = _plugin_manager.discover_plugins()
        return jsonify({'status': 'success', 'data': {'discovered': found}})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Plugin operation failed'}), 500


@app.route('/api/plugins/<name>/toggle', methods=['POST'])
@_require_api_key
@_rate_limit
def toggle_plugin(name):
    """Enable or disable a plugin."""
    if _plugin_manager is None:
        return jsonify({'status': 'error', 'data': 'Plugin system unavailable'}), 503
    body = request.get_json(silent=True)
    enabled = body.get('enabled', True) if body else True
    try:
        if _plugin_manager.toggle_plugin(name, enabled):
            return jsonify({'status': 'success', 'data': f'Plugin {"enabled" if enabled else "disabled"}'})
        return jsonify({'status': 'error', 'data': 'Plugin not found'}), 404
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Plugin operation failed'}), 500


# ---------------------------------------------------------------------------
# Notification API
# ---------------------------------------------------------------------------

@app.route('/api/notifications/channels', methods=['GET'])
@_require_api_key
@_rate_limit
def list_notification_channels():
    """List registered notification channels."""
    if _notification_manager is None:
        return jsonify({'status': 'error', 'data': 'Notification system unavailable'}), 503
    try:
        return jsonify({'status': 'success', 'data': _notification_manager.list_channels()})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Notification operation failed'}), 500


@app.route('/api/notifications/test', methods=['POST'])
@_require_api_key
@_rate_limit
def send_test_notification():
    """Send a test notification to verify channel configuration."""
    if _notification_manager is None:
        return jsonify({'status': 'error', 'data': 'Notification system unavailable'}), 503
    body = request.get_json(silent=True)
    channels = body.get('channels') if body else None
    try:
        results = _notification_manager.notify(
            title='ATOMIC Test Notification',
            message='This is a test notification from ATOMIC Framework.',
            severity='info',
            channels=channels,
        )
        return jsonify({'status': 'success', 'data': {'sent': results}})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Notification operation failed'}), 500


@app.route('/api/notifications/history', methods=['GET'])
@_require_api_key
@_rate_limit
def get_notification_history():
    """Get notification history."""
    if _notification_manager is None:
        return jsonify({'status': 'error', 'data': 'Notification system unavailable'}), 503
    try:
        limit = request.args.get('limit', 50, type=int)
        return jsonify({'status': 'success', 'data': _notification_manager.get_history(limit=limit)})
    except Exception as exc:
        return jsonify({'status': 'error', 'data': 'Notification operation failed'}), 500


# ---------------------------------------------------------------------------
# Chat API — real-time team chat on the dashboard
# ---------------------------------------------------------------------------

@app.route('/api/chat/messages', methods=['GET'])
@_require_api_key
@_rate_limit
def get_chat_messages():
    """Return recent chat messages."""
    try:
        limit = request.args.get('limit', 50, type=int)
        limit = max(1, min(limit, _CHAT_MAX_MESSAGES))
        with _chat_lock:
            messages = list(_chat_messages[-limit:])
        return jsonify({'status': 'success', 'data': messages})
    except Exception:
        return jsonify({'status': 'error', 'data': 'Failed to retrieve messages'}), 500


def _create_chat_message(sender_raw, text_raw):
    """Validate, create, and store a chat message. Returns the message dict."""
    sender = str(sender_raw or 'Anonymous').strip()[:50] or 'Anonymous'
    text = str(text_raw).strip()[:2000]
    msg = {
        'id': uuid.uuid4().hex[:12],
        'sender': sender,
        'message': text,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
    with _chat_lock:
        _chat_messages.append(msg)
        while len(_chat_messages) > _CHAT_MAX_MESSAGES:
            _chat_messages.pop(0)
    return msg


@app.route('/api/chat/messages', methods=['POST'])
@_require_api_key
@_rate_limit
def post_chat_message():
    """Send a new chat message. Broadcasts via WebSocket if available."""
    body = request.get_json(silent=True)
    if not body or not isinstance(body.get('message'), str) or not body['message'].strip():
        return jsonify({'status': 'error', 'data': 'Missing or empty message'}), 400

    msg = _create_chat_message(body.get('sender', 'Anonymous'), body['message'])
    _emit_ws('chat_message', msg)

    return jsonify({'status': 'success', 'data': msg}), 201


@app.route('/api/chat/messages', methods=['DELETE'])
@_require_api_key
@_rate_limit
def clear_chat_messages():
    """Clear all chat messages."""
    with _chat_lock:
        _chat_messages.clear()
    _emit_ws('chat_cleared', {})
    return jsonify({'status': 'success', 'data': 'Chat cleared'})


# ---------------------------------------------------------------------------
# AI Brain API — AI Engine summary, predictions, and strategy
# ---------------------------------------------------------------------------

def _get_ai_engine_for_scan(scan_id=None):
    """Get AIEngine from an active scan, or create a standalone one."""
    if scan_id:
        scan_info = _active_scans.get(scan_id)
        if scan_info and scan_info.get('engine'):
            engine = scan_info['engine']
            if hasattr(engine, 'ai') and engine.ai is not None:
                return engine.ai
    # Create a lightweight standalone AIEngine with a minimal mock engine
    if _AI_ENGINE_AVAILABLE:
        try:
            class _MiniEngine:
                config = {'verbose': False}
            return AIEngine(_MiniEngine())
        except Exception:
            pass
    return None


@app.route('/api/ai/summary', methods=['GET'])
@_require_api_key
@_rate_limit
def get_ai_summary():
    """Return AI engine summary including pattern counts and calibration."""
    scan_id = request.args.get('scan_id', '')
    ai = _get_ai_engine_for_scan(scan_id)
    if ai is None:
        return jsonify({'status': 'error', 'data': 'AI engine unavailable'}), 503
    try:
        summary = ai.get_ai_summary()
        summary['engine_available'] = True
        if _AI_ENGINE_AVAILABLE:
            from core.ai_engine import VULN_CORRELATIONS, EXPLOIT_DIFFICULTY
            summary['vuln_correlations_db'] = len(VULN_CORRELATIONS)
            summary['exploit_types_tracked'] = len(EXPLOIT_DIFFICULTY)
        return jsonify({'status': 'success', 'data': summary})
    except Exception:
        return jsonify({'status': 'error', 'data': 'AI summary failed'}), 500


@app.route('/api/ai/predictions', methods=['POST'])
@_require_api_key
@_rate_limit
def get_ai_predictions():
    """Get AI vulnerability predictions for a URL/parameter."""
    body = request.get_json(silent=True)
    if not body or not body.get('url'):
        return jsonify({'status': 'error', 'data': 'Missing url'}), 400
    ai = _get_ai_engine_for_scan(body.get('scan_id', ''))
    if ai is None:
        return jsonify({'status': 'error', 'data': 'AI engine unavailable'}), 503
    try:
        predictions = ai.predict_vulnerabilities(
            body['url'],
            body.get('param_name', ''),
            body.get('param_value', ''),
        )
        return jsonify({'status': 'success', 'data': predictions})
    except Exception:
        return jsonify({'status': 'error', 'data': 'Prediction failed'}), 500


@app.route('/api/ai/correlations', methods=['GET'])
@_require_api_key
@_rate_limit
def get_ai_correlations():
    """Return the vulnerability correlation database."""
    if not _AI_ENGINE_AVAILABLE:
        return jsonify({'status': 'error', 'data': 'AI engine unavailable'}), 503
    try:
        from core.ai_engine import VULN_CORRELATIONS, EXPLOIT_DIFFICULTY
        corr = [
            {'pair': list(k), 'chain': v['chain'], 'boost': v['boost'], 'label': v['label']}
            for k, v in VULN_CORRELATIONS.items()
        ]
        diff = {
            k: {'base_difficulty': v['base'], 'defense_factors': v['factors']}
            for k, v in EXPLOIT_DIFFICULTY.items()
        }
        return jsonify({'status': 'success', 'data': {
            'correlations': corr,
            'exploit_difficulty': diff,
        }})
    except Exception:
        return jsonify({'status': 'error', 'data': 'Correlations failed'}), 500


# ---------------------------------------------------------------------------
# Ollama API — Local LLM integration for security analysis
# ---------------------------------------------------------------------------

def _ollama_available():
    """Check if ollama binary is available on the system."""
    try:
        result = subprocess.run(
            ['ollama', '--version'],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _ollama_request(path, method='GET', json_data=None, timeout=120):
    """Make an HTTP request to the local Ollama API server."""
    import urllib.request
    import urllib.error
    base = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
    url = f'{base}{path}'
    req_data = json.dumps(json_data).encode() if json_data else None
    req = urllib.request.Request(
        url, data=req_data, method=method,
        headers={'Content-Type': 'application/json'} if req_data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            json.JSONDecodeError):
        return None


@app.route('/api/ollama/status', methods=['GET'])
@_require_api_key
@_rate_limit
def ollama_status():
    """Check Ollama installation and running status."""
    installed = _ollama_available()
    running = False
    models = []
    if installed:
        tags = _ollama_request('/api/tags')
        if tags is not None:
            running = True
            models = [
                {
                    'name': m.get('name', ''),
                    'size': m.get('size', 0),
                    'modified': m.get('modified_at', ''),
                }
                for m in tags.get('models', [])
            ]
    return jsonify({'status': 'success', 'data': {
        'installed': installed,
        'running': running,
        'models': models,
        'ollama_host': os.environ.get('OLLAMA_HOST', 'http://localhost:11434'),
    }})


@app.route('/api/ollama/install', methods=['POST'])
@_require_api_key
@_rate_limit
def ollama_install_info():
    """Return install instructions for Ollama (cannot auto-install on server)."""
    return jsonify({'status': 'success', 'data': {
        'message': 'Run the command below on your server to install Ollama',
        'linux': 'curl -fsSL https://ollama.com/install.sh | sh',
        'macos': 'brew install ollama',
        'windows': 'Download from https://ollama.com/download',
        'docker': 'docker run -d -p 11434:11434 --name ollama ollama/ollama',
        'start_command': 'ollama serve',
        'pull_model': 'ollama pull llama3.2',
    }})


@app.route('/api/ollama/pull', methods=['POST'])
@_require_api_key
@_rate_limit
def ollama_pull_model():
    """Pull/download an Ollama model."""
    body = request.get_json(silent=True)
    model_name = body.get('model', '') if body else ''
    if not model_name or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$', model_name) or '..' in model_name:
        return jsonify({'status': 'error', 'data': 'Invalid model name'}), 400
    result = _ollama_request('/api/pull', method='POST',
                             json_data={'name': model_name, 'stream': False},
                             timeout=600)
    if result is not None:
        return jsonify({'status': 'success', 'data': {
            'model': model_name, 'message': 'Model pulled successfully',
        }})
    return jsonify({'status': 'error',
                    'data': 'Failed to pull model — is Ollama running?'}), 502


@app.route('/api/ollama/chat', methods=['POST'])
@_require_api_key
@_rate_limit
def ollama_chat():
    """Chat with an Ollama model for security analysis."""
    body = request.get_json(silent=True)
    if not body or not isinstance(body.get('message'), str) or not body['message'].strip():
        return jsonify({'status': 'error', 'data': 'Missing or empty message'}), 400

    model = body.get('model', 'llama3.2')
    user_msg = body['message'].strip()[:4000]
    system_prompt = body.get('system_prompt',
        'You are a cybersecurity AI assistant integrated into the ATOMIC '
        'vulnerability scanning framework. Help the user analyze '
        'vulnerabilities, interpret scan results, suggest remediation, '
        'and explain security concepts. Be concise and technical.'
    )

    # Build conversation messages
    with _ollama_lock:
        messages = [{'role': 'system', 'content': system_prompt}]
        messages.extend(_ollama_chat_history[-_OLLAMA_CONTEXT_MESSAGES:])
        messages.append({'role': 'user', 'content': user_msg})

    result = _ollama_request('/api/chat', method='POST', json_data={
        'model': model,
        'messages': messages,
        'stream': False,
    }, timeout=120)

    if result is None:
        return jsonify({'status': 'error',
                        'data': 'Ollama unavailable — is it running?'}), 502

    assistant_msg = result.get('message', {}).get('content', '')

    # Store in history
    with _ollama_lock:
        _ollama_chat_history.append({'role': 'user', 'content': user_msg})
        _ollama_chat_history.append({'role': 'assistant', 'content': assistant_msg})
        while len(_ollama_chat_history) > _OLLAMA_MAX_HISTORY:
            _ollama_chat_history.pop(0)

    return jsonify({'status': 'success', 'data': {
        'response': assistant_msg,
        'model': model,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }})


@app.route('/api/ollama/chat/history', methods=['GET'])
@_require_api_key
@_rate_limit
def ollama_chat_history():
    """Return Ollama chat history."""
    with _ollama_lock:
        return jsonify({'status': 'success', 'data': list(_ollama_chat_history)})


@app.route('/api/ollama/chat/history', methods=['DELETE'])
@_require_api_key
@_rate_limit
def ollama_clear_history():
    """Clear Ollama chat history."""
    with _ollama_lock:
        _ollama_chat_history.clear()
    return jsonify({'status': 'success', 'data': 'Chat history cleared'})


# ---------------------------------------------------------------------------
# SocketIO event handlers (real-time WebSocket updates)
# ---------------------------------------------------------------------------

if SOCKETIO_AVAILABLE and socketio is not None:
    @socketio.on('connect')
    def handle_connect():
        """Client connected — send current active scans."""
        with _scans_lock:
            active = {
                sid: {
                    'status': info.get('status'),
                    'target': info.get('target'),
                    'findings': info.get('findings', 0),
                    'start_time': info.get('start_time'),
                }
                for sid, info in _active_scans.items()
                if info.get('status') == 'running'
            }
        emit('active_scans', active)

    @socketio.on('subscribe_scan')
    def handle_subscribe(data):
        """Client wants live events for a specific scan."""
        scan_id = data.get('scan_id', '') if isinstance(data, dict) else ''
        if not scan_id or not _validate_shell_id(scan_id):
            return
        scan_info = _active_scans.get(scan_id)
        if scan_info and scan_info.get('engine'):
            engine = scan_info['engine']
            if hasattr(engine, 'get_pipeline_state'):
                emit('pipeline_state', engine.get_pipeline_state())

    @socketio.on('shell_command')
    def handle_shell_command(data):
        """Execute a shell command via WebSocket."""
        if not isinstance(data, dict):
            return
        shell_id = data.get('shell_id', '')
        cmd = data.get('command', '').strip()
        if not shell_id or not cmd:
            emit('shell_output', {'error': 'Missing shell_id or command'})
            return
        if not _validate_shell_id(shell_id):
            emit('shell_output', {'error': 'Invalid shell ID'})
            return
        try:
            from modules.shell.manager import ShellManager
            manager = ShellManager()
            result = manager.execute_command(shell_id, cmd)
            emit('shell_output', {
                'shell_id': shell_id,
                'command': cmd,
                'output': result or '',
            })
        except Exception as exc:
            logger.error('WS shell execute error: %s', exc)
            emit('shell_output', {'error': 'Command execution failed'})

    @socketio.on('chat_message')
    def handle_chat_message(data):
        """Receive a chat message via WebSocket and broadcast to all clients."""
        if not isinstance(data, dict):
            return
        text = str(data.get('message', '')).strip()
        if not text:
            return
        msg = _create_chat_message(data.get('sender', 'Anonymous'), text)
        emit('chat_message', msg, broadcast=True)


# ---------------------------------------------------------------------------
# App factory & runner
# ---------------------------------------------------------------------------

def create_app(host='0.0.0.0', port=5000, debug=False):
    """Configure and return the Flask application and a convenience runner."""
    app.config['HOST'] = host
    app.config['PORT'] = port
    app.config['DEBUG'] = debug

    os.makedirs(Config.REPORTS_DIR, exist_ok=True)

    # Wire the scheduler to trigger scans via _run_scan
    if _scheduler is not None:
        def _scheduler_callback(entry):
            scan_id = str(uuid.uuid4())[:8]
            config_overrides = entry.config if entry.config else {}
            cfg = {**Config.__dict__, **config_overrides}
            threading.Thread(
                target=_run_scan, args=(scan_id, entry.target, cfg),
                daemon=True, name=f'sched-scan-{scan_id}',
            ).start()
        _scheduler.set_scan_callback(_scheduler_callback)

    def run_app():
        logger.info("Starting ATOMIC Dashboard on http://%s:%s", host, port)
        if _API_KEY:
            logger.info("API key authentication enabled")
        else:
            logger.warning("No ATOMIC_API_KEY set — API endpoints are open")
        logger.warning("FOR AUTHORIZED TESTING ONLY")
        # Use SocketIO runner if available (enables WebSocket), else plain Flask
        if socketio is not None:
            socketio.run(app, host=host, port=port, debug=debug,
                         allow_unsafe_werkzeug=debug)
        else:
            app.run(host=host, port=port, debug=debug)

    return app, run_app


if __name__ == '__main__':
    _, runner = create_app(debug=os.environ.get('FLASK_DEBUG', '').lower() == '1')
    runner()
