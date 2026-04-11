import os
import json
import secrets
import re
from datetime import datetime, timedelta, timezone

import bcrypt
import psycopg2
import psycopg2.extras
from flask import Flask, request, session, jsonify, send_from_directory, abort
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

socketio = SocketIO(app, cors_allowed_origins='*', async_mode='gevent')

# Railway sets DATABASE_URL as postgres://, psycopg2 needs postgresql://
DATABASE_URL = os.environ.get('DATABASE_URL', '').replace('postgres://', 'postgresql://', 1)


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username     TEXT PRIMARY KEY,
                    name         TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role         TEXT NOT NULL DEFAULT 'auditor',
                    created_at   TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS progress (
                    username   TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
                    data       JSONB,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS magic_tokens (
                    token      TEXT PRIMARY KEY,
                    username   TEXT REFERENCES users(username) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    used_at    TIMESTAMPTZ
                );
            """)
            # If ADMIN_PASSWORD env var is explicitly set, always update the hash on startup.
            # If not set, only create the admin user on first run (don't overwrite).
            admin_pass_env = os.environ.get('ADMIN_PASSWORD')
            if admin_pass_env:
                admin_hash = bcrypt.hashpw(admin_pass_env.encode(), bcrypt.gensalt()).decode()
                cur.execute("""
                    INSERT INTO users (username, name, password_hash, role)
                    VALUES ('admin', 'Administrator', %s, 'admin')
                    ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
                """, (admin_hash,))
            else:
                default_hash = bcrypt.hashpw(b'Admin2024!', bcrypt.gensalt()).decode()
                cur.execute("""
                    INSERT INTO users (username, name, password_hash, role)
                    VALUES ('admin', 'Administrator', %s, 'admin')
                    ON CONFLICT (username) DO NOTHING
                """, (default_hash,))
        conn.commit()
    finally:
        conn.close()


# ── Auth helpers ──────────────────────────────────────────────────────────────

def current_user():
    return session.get('user')


def require_role(*roles):
    user = current_user()
    if not user:
        abort(401)
    if user['role'] not in roles:
        abort(403)
    return user


# ── One-time setup endpoint ───────────────────────────────────────────────────

@app.route('/setup/<token>')
def setup(token):
    """
    Visit /setup/<SETUP_TOKEN> to create tables and admin user.
    Set SETUP_TOKEN as an env var in Railway before calling this.
    Remove or change SETUP_TOKEN after setup is complete.
    """
    expected = os.environ.get('SETUP_TOKEN')
    if not expected or token != expected:
        abort(403)
    try:
        init_db()
        return '<h2>✅ Database tables created and admin user initialised.</h2><p>You can now <a href="/admin.html">log in to the admin panel</a>.</p>', 200
    except Exception as e:
        return f'<h2>❌ Setup failed</h2><pre>{e}</pre>', 500


# ── Static pages ──────────────────────────────────────────────────────────────

@app.route('/')
@app.route('/index.html')
def serve_index():
    return send_from_directory('.', 'index.html')


@app.route('/admin.html')
def serve_admin():
    return send_from_directory('.', 'admin.html')


# ── Auth API ──────────────────────────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(force=True)
    username = (data.get('username') or '').strip().lower()
    password = (data.get('password') or '').strip().encode()

    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                'SELECT username, name, role, password_hash FROM users WHERE username = %s',
                (username,)
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if not row or not bcrypt.checkpw(password, row['password_hash'].encode()):
        return jsonify({'error': 'Invalid username or password'}), 401

    session['user'] = {
        'username': row['username'],
        'role': row['role'],
        'name': row['name'],
    }
    return jsonify(session['user'])


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/me')
def api_me():
    user = current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(user)


# ── Users API (admin only) ────────────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
def api_get_users():
    require_role('admin')
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.username, u.name, u.created_at,
                       p.data AS progress, p.updated_at
                FROM users u
                LEFT JOIN progress p ON p.username = u.username
                WHERE u.role = 'auditor'
                ORDER BY u.created_at
            """)
            rows = cur.fetchall()
    finally:
        conn.close()

    return jsonify([
        {
            'username': r['username'],
            'name': r['name'],
            'createdAt': r['created_at'].isoformat() if r['created_at'] else None,
            'progress': r['progress'],
        }
        for r in rows
    ])


@app.route('/api/users', methods=['POST'])
def api_create_user():
    require_role('admin')
    data = request.get_json(force=True)
    name     = (data.get('name') or '').strip()
    username = (data.get('username') or '').strip().lower()
    password = (data.get('password') or '').strip()

    if not name or not username or not password:
        return jsonify({'error': 'All fields required'}), 400
    if len(password) < 12:
        return jsonify({'error': 'Password must be at least 12 characters'}), 400
    if username == 'admin':
        return jsonify({'error': '"admin" is a reserved username'}), 400
    if not re.match(r'^[a-z0-9_]+$', username):
        return jsonify({'error': 'Username: only lowercase letters, numbers, and _'}), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    'INSERT INTO users (username, name, password_hash, role) VALUES (%s, %s, %s, %s)',
                    (username, name, password_hash, 'auditor')
                )
                conn.commit()
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                return jsonify({'error': 'Username already exists'}), 409
    finally:
        conn.close()

    return jsonify({'username': username, 'name': name}), 201


@app.route('/api/users/<username>', methods=['DELETE'])
def api_delete_user(username):
    require_role('admin')
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                'DELETE FROM users WHERE username = %s AND role = %s',
                (username, 'auditor')
            )
            if cur.rowcount == 0:
                return jsonify({'error': 'User not found'}), 404
        conn.commit()
    finally:
        conn.close()

    socketio.emit('user_deleted', {'username': username}, room='admin')
    return '', 204


@app.route('/api/users/<username>/magic-link', methods=['POST'])
def api_magic_link(username):
    require_role('admin')
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                'SELECT username FROM users WHERE username = %s AND role = %s',
                (username, 'auditor')
            )
            if not cur.fetchone():
                return jsonify({'error': 'User not found'}), 404
            # Invalidate previous unused tokens for this user
            cur.execute(
                'DELETE FROM magic_tokens WHERE username = %s AND used_at IS NULL',
                (username,)
            )
            token = secrets.token_urlsafe(32)
            cur.execute(
                'INSERT INTO magic_tokens (token, username) VALUES (%s, %s)',
                (token, username)
            )
        conn.commit()
    finally:
        conn.close()

    base = request.host_url.rstrip('/')
    url = f"{base}/index.html?join={token}"
    return jsonify({'token': token, 'url': url})


# ── Progress API ──────────────────────────────────────────────────────────────

@app.route('/api/progress', methods=['GET'])
def api_get_progress():
    user = require_role('auditor')
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT data FROM progress WHERE username = %s', (user['username'],))
            row = cur.fetchone()
    finally:
        conn.close()

    return jsonify(row['data'] if row else None)


@app.route('/api/progress', methods=['POST'])
def api_save_progress():
    user = require_role('auditor')
    data = request.get_json(force=True)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO progress (username, data, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (username)
                DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
            """, (user['username'], json.dumps(data)))
        conn.commit()
    finally:
        conn.close()

    # Push live update to admin dashboard
    socketio.emit('progress_update', {
        'username': user['username'],
        'name':     user['name'],
        'progress': data,
    }, room='admin')

    return jsonify({'ok': True})


# ── Admin password change ─────────────────────────────────────────────────────

@app.route('/api/admin/change-password', methods=['POST'])
def api_change_password():
    user = require_role('admin')
    data = request.get_json(force=True)
    current = (data.get('current') or '').strip().encode()
    new_pw  = (data.get('new') or '').strip()

    if not current or not new_pw:
        return jsonify({'error': 'Both fields are required'}), 400
    if len(new_pw) < 12:
        return jsonify({'error': 'New password must be at least 12 characters'}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT password_hash FROM users WHERE username = %s', (user['username'],))
            row = cur.fetchone()
            if not row or not bcrypt.checkpw(current, row['password_hash'].encode()):
                return jsonify({'error': 'Current password is incorrect'}), 401
            new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            cur.execute('UPDATE users SET password_hash = %s WHERE username = %s',
                        (new_hash, user['username']))
        conn.commit()
    finally:
        conn.close()

    return jsonify({'ok': True})


# ── Magic link join ───────────────────────────────────────────────────────────

@app.route('/api/join/<token>', methods=['GET'])
def api_join_check(token):
    """Return the invitee's name if the token is valid — no login yet."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT t.username, u.name, t.created_at
                FROM magic_tokens t
                JOIN users u ON u.username = t.username
                WHERE t.token = %s AND t.used_at IS NULL
            """, (token,))
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({'error': 'Invalid or already-used link'}), 404
    if datetime.now(timezone.utc) - row['created_at'] > timedelta(hours=48):
        return jsonify({'error': 'Link has expired (48 h)'}), 410

    return jsonify({'username': row['username'], 'name': row['name']})


@app.route('/api/join/<token>', methods=['POST'])
def api_join_confirm(token):
    """Auditor confirms — mark token used and create session."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT t.username, u.name, t.created_at
                FROM magic_tokens t
                JOIN users u ON u.username = t.username
                WHERE t.token = %s AND t.used_at IS NULL
            """, (token,))
            row = cur.fetchone()

            if not row:
                return jsonify({'error': 'Invalid or already-used link'}), 404
            if datetime.now(timezone.utc) - row['created_at'] > timedelta(hours=48):
                return jsonify({'error': 'Link has expired'}), 410

            cur.execute('UPDATE magic_tokens SET used_at = NOW() WHERE token = %s', (token,))
        conn.commit()
    finally:
        conn.close()

    session['user'] = {'username': row['username'], 'role': 'auditor', 'name': row['name']}
    return jsonify(session['user'])


# ── Socket.IO ─────────────────────────────────────────────────────────────────

@socketio.on('join_admin')
def on_join_admin():
    user = current_user()
    if user and user['role'] == 'admin':
        join_room('admin')
        emit('joined', {'room': 'admin'})


# ── Startup ───────────────────────────────────────────────────────────────────

try:
    init_db()
    print('Database initialised.')
except Exception as e:
    print(f'Warning: DB init failed — {e}')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
