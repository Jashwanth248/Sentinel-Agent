"""Execution boundary for untrusted model tool calls.

Only invoke() belongs on the agent-facing surface. Provisioning, approval and
kill-switch methods belong to the trusted host, never to an agent tool registry.
The SQLite connector implements local documents and a durable export outbox.
It does not send network traffic. See docs/GATEWAY.md for deployment boundaries.
"""
import hashlib
import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager


LEVELS = {'public': 0, 'internal': 1, 'confidential': 2}
SCHEMAS = {
    'read_document': {'document_id'},
    'export_document': {'document_id', 'destination'},
    'delete_document': {'document_id'},
}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


class Denied(Exception):
    pass


class Gateway:
    def __init__(self, database, *, clock=time.time):
        self.clock = clock
        self.lock = threading.RLock()
        self.db = sqlite3.connect(database, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL);
            INSERT OR IGNORE INTO state VALUES (1, 1);
            CREATE TABLE IF NOT EXISTS documents (
                tenant TEXT, id TEXT, label TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (tenant, id));
            CREATE TABLE IF NOT EXISTS destinations (
                tenant TEXT, id TEXT, clearance TEXT NOT NULL, PRIMARY KEY (tenant, id));
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, tenant TEXT NOT NULL, actor TEXT NOT NULL,
                tools TEXT NOT NULL, clearance TEXT NOT NULL, expires REAL NOT NULL,
                remaining INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS approvals (
                token TEXT PRIMARY KEY, session TEXT NOT NULL, command TEXT NOT NULL,
                approver TEXT NOT NULL, expires REAL NOT NULL, document_hash TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS requests (
                session TEXT, id TEXT, PRIMARY KEY (session, id));
            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, destination TEXT NOT NULL,
                document_id TEXT NOT NULL, label TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, session TEXT NOT NULL,
                request_id TEXT NOT NULL, command_hash TEXT NOT NULL,
                outcome TEXT NOT NULL, reason TEXT NOT NULL);
        ''')

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise

    def close(self):
        self.db.close()

    def put_document(self, tenant, document_id, body, label='internal'):
        """Trusted provisioning: classifications never come from model arguments."""
        if label not in LEVELS:
            raise ValueError('Unknown classification')
        with self.transaction():
            self.db.execute('INSERT OR REPLACE INTO documents VALUES (?, ?, ?, ?)',
                            (tenant, document_id, label, body))

    def add_destination(self, tenant, destination, clearance='internal'):
        if clearance not in LEVELS:
            raise ValueError('Unknown classification')
        with self.transaction():
            self.db.execute('INSERT OR REPLACE INTO destinations VALUES (?, ?, ?)',
                            (tenant, destination, clearance))

    def create_session(self, tenant, actor, tools, *, clearance='internal', ttl=300, budget=20):
        """Trusted host mints a scoped bearer capability after authenticating a user."""
        if (not tenant or not actor or clearance not in LEVELS or
                not set(tools) <= SCHEMAS.keys() or ttl <= 0 or budget <= 0):
            raise ValueError('Invalid session policy')
        token = secrets.token_urlsafe(32)
        with self.transaction():
            self.db.execute('INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?)',
                            (digest(token), tenant, actor, canonical(sorted(set(tools))),
                             clearance, self.clock()+ttl, budget))
        return token

    def set_enabled(self, enabled):
        with self.transaction():
            self.db.execute('UPDATE state SET enabled=? WHERE id=1', (bool(enabled),))

    @staticmethod
    def validate(request):
        if not isinstance(request, dict) or set(request) != {'id', 'tool', 'arguments'}:
            raise Denied('invalid_request')
        if not isinstance(request['id'], str) or not 1 <= len(request['id']) <= 128:
            raise Denied('invalid_request')
        tool, args = request['tool'], request['arguments']
        if not isinstance(tool, str) or tool not in SCHEMAS:
            raise Denied('unknown_tool')
        if not isinstance(args, dict) or set(args) != SCHEMAS[tool]:
            raise Denied('invalid_arguments')
        if any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in args.values()):
            raise Denied('invalid_arguments')
        return digest(canonical({'tool': tool, 'arguments': args}))

    def approve(self, session_token, request, *, approver, ttl=60):
        """Trusted control plane only. An agent cannot supply an approval identity."""
        command = self.validate(request)
        if request['tool'] != 'delete_document' or not approver or not 0 < ttl <= 300:
            raise ValueError('Invalid approval')
        token = secrets.token_urlsafe(32)
        with self.transaction():
            session = self.db.execute('SELECT * FROM sessions WHERE token=?',
                                      (digest(session_token),)).fetchone()
            if session is None or session['expires'] <= self.clock():
                raise ValueError('Inactive session')
            document = self.db.execute('SELECT * FROM documents WHERE tenant=? AND id=?',
                (session['tenant'], request['arguments']['document_id'])).fetchone()
            if document is None:
                raise ValueError('Unavailable document')
            self.db.execute('INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, 0)',
                            (digest(token), digest(session_token), command, approver,
                             min(self.clock()+ttl, session['expires']), digest(canonical(dict(document)))))
        return token

    def invoke(self, session_token, request, *, approval_token=None):
        """Validate, authorize, audit and execute atomically; errors deny execution.

        The host passes its capability outside model-produced arguments. Never
        include bearer capabilities in prompts, model memory or model outputs.
        """
        session_id = digest(session_token) if isinstance(session_token, str) else ''
        request_id, command = '', ''
        with self.transaction():
            try:
                session = self.db.execute('SELECT * FROM sessions WHERE token=?',
                                          (session_id,)).fetchone()
                if session is None:
                    raise Denied('unauthenticated')
                if not self.db.execute('SELECT enabled FROM state WHERE id=1').fetchone()[0]:
                    raise Denied('gateway_disabled')
                if session['expires'] <= self.clock():
                    raise Denied('session_expired')
                if session['remaining'] <= 0:
                    raise Denied('budget_exhausted')
                self.db.execute('UPDATE sessions SET remaining=remaining-1 WHERE token=?',
                                (session_id,))
                command = self.validate(request)
                request_id = request['id']
                if self.db.execute('SELECT 1 FROM requests WHERE session=? AND id=?',
                                   (session_id, request_id)).fetchone():
                    raise Denied('replayed_request')
                self.db.execute('INSERT INTO requests VALUES (?, ?)', (session_id, request_id))
                tool, args = request['tool'], request['arguments']
                if tool not in json.loads(session['tools']):
                    raise Denied('tool_not_granted')
                document = self.db.execute('SELECT * FROM documents WHERE tenant=? AND id=?',
                                          (session['tenant'], args['document_id'])).fetchone()
                if document is None or LEVELS[document['label']] > LEVELS[session['clearance']]:
                    raise Denied('resource_not_authorized')
                if tool == 'read_document':
                    result = {'document_id': document['id'], 'label': document['label'],
                              'body': document['body'], 'content_trust': 'untrusted'}
                elif tool == 'export_document':
                    destination = self.db.execute(
                        'SELECT * FROM destinations WHERE tenant=? AND id=?',
                        (session['tenant'], args['destination'])).fetchone()
                    if destination is None:
                        raise Denied('destination_not_allowed')
                    if LEVELS[document['label']] > LEVELS[destination['clearance']]:
                        raise Denied('classification_violation')
                    cursor = self.db.execute(
                        'INSERT INTO outbox (tenant,destination,document_id,label,body) VALUES (?,?,?,?,?)',
                        (session['tenant'], destination['id'], document['id'],
                         document['label'], document['body']))
                    result = {'outbox_id': cursor.lastrowid, 'delivery': 'queued_locally'}
                else:
                    approval = self.db.execute('SELECT * FROM approvals WHERE token=?',
                        (digest(approval_token) if isinstance(approval_token, str) else '',)).fetchone()
                    if (approval is None or approval['session'] != session_id or
                            approval['command'] != command or approval['used'] or
                            approval['expires'] <= self.clock() or
                            approval['document_hash'] != digest(canonical(dict(document)))):
                        raise Denied('valid_approval_required')
                    self.db.execute('UPDATE approvals SET used=1 WHERE token=?', (approval['token'],))
                    self.db.execute('DELETE FROM documents WHERE tenant=? AND id=?',
                                    (session['tenant'], document['id']))
                    result = {'deleted': document['id']}
                outcome, reason = 'allowed', 'policy_satisfied'
            except Denied as error:
                outcome, reason, result = 'denied', str(error), None
            self.db.execute('INSERT INTO audit (timestamp,session,request_id,command_hash,outcome,reason) '
                            'VALUES (?,?,?,?,?,?)',
                            (self.clock(), session_id, digest(request_id), command, outcome, reason))
        return {'outcome': outcome, 'reason': reason, 'result': result}

    def audit_records(self):
        """Trusted operator access; not an agent tool."""
        with self.lock:
            return [dict(row) for row in self.db.execute('SELECT * FROM audit ORDER BY id')]
