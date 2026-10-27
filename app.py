"""Local-only authenticated web application. Run: python3 app.py"""
import datetime
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from engine import target, header_check, nmap_check, sql_review, report

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('BOUNTY_DATA', str(ROOT / 'data')))
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.Lock()


def db():
    conn = sqlite3.connect(DATA / 'workbench.sqlite3')
    conn.row_factory = sqlite3.Row
    return conn


def initialize():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    with db() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, created TEXT, target TEXT, mode TEXT, policy TEXT, rules TEXT, findings TEXT)')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Do not log authorization tokens, submitted source, or policy text.

    def send(self, code, body, kind='application/json; charset=utf-8'):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def permitted(self):
        if self.headers.get('Host') not in ('127.0.0.1:8765', 'localhost:8765'):
            self.send(403, {'error': 'Invalid Host'})
            return False
        origin = self.headers.get('Origin')
        if origin and origin not in ('http://127.0.0.1:8765', 'http://localhost:8765'):
            self.send(403, {'error': 'Invalid Origin'})
            return False
        supplied = self.headers.get('Authorization', '')
        if not hmac.compare_digest(supplied, 'Bearer ' + TOKEN):
            self.send(401, {'error': 'Enter the session token shown in your terminal'})
            return False
        return True

    def do_GET(self):
        path = urlsplit(self.path).path
        static = {'/': ('index.html', 'text/html; charset=utf-8'), '/ui.js': ('ui.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
        if path in static:
            name, kind = static[path]
            self.send(200, (ROOT / 'web' / name).read_bytes(), kind)
            return
        if not self.permitted():
            return
        if path == '/api/jobs':
            with db() as conn:
                rows = conn.execute('SELECT id, created, target, mode FROM jobs ORDER BY created DESC LIMIT 100').fetchall()
            self.send(200, [dict(r) for r in rows])
        elif path.startswith('/api/report/'):
            job_id = path.rsplit('/', 1)[-1]
            with db() as conn:
                row = conn.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            if not row:
                self.send(404, {'error': 'Unknown assessment'})
            else:
                self.send(200, report(dict(row), json.loads(row['findings'])).encode(), 'text/markdown; charset=utf-8')
        else:
            self.send(404, {'error': 'Not found'})

    def do_POST(self):
        if not self.permitted():
            return
        if self.path != '/api/run':
            self.send(404, {'error': 'Not found'})
            return
        if not LOCK.acquire(blocking=False):
            self.send(409, {'error': 'One assessment is already running'})
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if size <= 0 or size > 250000:
                raise ValueError('Body must be between 1 and 250000 bytes')
            request = json.loads(self.rfile.read(size))
            if not isinstance(request, dict):
                raise ValueError('Expected a JSON object')
            mode = request.get('mode')
            if mode not in ('headers', 'nmap', 'sql-local'):
                raise ValueError('Unknown assessment mode')
            rules = str(request.get('rules', '')).strip()
            policy = str(request.get('policy', '')).strip()
            if len(rules) < 30 or not policy or request.get('authorized') is not True:
                raise ValueError('Provide policy, explicit scope/exclusions/method rules and authorization')
            asset = str(request.get('target', '')).strip()
            if mode != 'sql-local':
                target(asset)
                if request.get('scope') != asset:
                    raise ValueError('Repeat the exact authorized URL to approve this one-asset plan')
            else:
                asset = 'User-supplied local source text'
            if mode == 'headers':
                findings = header_check(asset)
            elif mode == 'nmap':
                if request.get('host_authorized') is not True:
                    raise ValueError('Explicit permission for host/port scanning is required')
                findings = nmap_check(asset)
            else:
                findings = sql_review(str(request.get('source', '')))
            job = dict(id=secrets.token_hex(8), created=datetime.datetime.now(datetime.timezone.utc).isoformat(), target=asset, mode=mode, policy=policy, rules=rules)
            with db() as conn:
                conn.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)', (*job.values(), json.dumps(findings)))
            self.send(200, {'id': job['id'], 'findings': findings})
        except Exception as exc:
            # Avoid echoing network errors that can contain remote-controlled strings.
            message = str(exc) if isinstance(exc, ValueError) else 'Assessment stopped; no automatic retry. Check environment and authorized target.'
            self.send(400, {'error': message})
        finally:
            LOCK.release()


if __name__ == '__main__':
    initialize()
    print('Open http://127.0.0.1:8765')
    print('Session token:', TOKEN, flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
