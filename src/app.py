import os
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app, supports_credentials=True)

# Database setup
DB_PATH = "conference.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                date TIMESTAMP NOT NULL,
                type TEXT NOT NULL,
                duration INTEGER NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS connection_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')
        conn.commit()

# Initialize database
if not os.path.exists(DB_PATH):
    init_db()

# Email configuration (update with your SMTP settings)
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'your_email@gmail.com',  # Replace with actual email
    'sender_password': 'your_app_password'   # Replace with actual app password
}

def send_reset_email(email, token):
    reset_url = f"http://localhost:5000/reset-password?token={token}"
    msg = MIMEText(f"Click the link to reset your password: {reset_url}\nThis link expires in 1 hour.")
    msg['Subject'] = 'Conference Management System - Password Reset'
    msg['From'] = EMAIL_CONFIG['sender_email']
    msg['To'] = email

    try:
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')

@app.route('/reset-password')
def reset_password():
    return render_template('reset-password.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT full_name, email FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if not user:
            return redirect(url_for('login'))
        full_name, email = user
    return render_template('dashboard.html', csrf_token=secrets.token_hex(16), full_name=full_name, email=email)

@app.route('/networking')
def networking():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT full_name, email FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if not user:
            return redirect(url_for('login'))
        full_name, email = user
    return render_template('networking-page.html', csrf_token=secrets.token_hex(16), full_name=full_name, email=email)

@app.route('/clicked-profile')
def clicked_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get the user ID from query parameters
    user_id = request.args.get('userId')
    if not user_id:
        return redirect(url_for('networking'))
    
    # Fetch user data from database
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id, full_name, email FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        
        if not user:
            return redirect(url_for('networking'))
    
    return render_template(
        'clicked-profile.html',
        csrf_token=secrets.token_hex(16),
        user_id=user[0],
        full_name=user[1],
        email=user[2]
    )

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT full_name, email FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if not user:
            return redirect(url_for('login'))
        full_name, email = user
    return render_template('profile.html', csrf_token=secrets.token_hex(16), full_name=full_name, email=email)

@app.route('/sessions')
def sessions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT full_name, email FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if not user:
            return redirect(url_for('login'))
        full_name, email = user
    return render_template('sessions.html', csrf_token=secrets.token_hex(16), full_name=full_name, email=email)

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT full_name, email FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if not user:
            return redirect(url_for('login'))
        full_name, email = user
    return render_template('settings.html', csrf_token=secrets.token_hex(16), full_name=full_name, email=email)

@app.route('/api/user', methods=['GET'])
def api_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT full_name, email FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'name': user[0],
            'email': user[1]
        }), 200

@app.route('/api/sessions', methods=['GET'])
def api_sessions():
    recent = request.args.get('recent', default='false', type=str).lower() == 'true'
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        query = 'SELECT id, title, description, date, type, duration FROM sessions'
        if recent:
            query += ' ORDER BY date DESC LIMIT 10'
        c.execute(query)
        sessions = c.fetchall()
        
        return jsonify([
            {
                'id': s[0],
                'title': s[1],
                'description': s[2],
                'date': s[3],
                'type': s[4],
                'duration': s[5]
            } for s in sessions
        ]), 200

@app.route('/api/sessions/<session_id>/join', methods=['POST'])
def api_join_session(session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM sessions WHERE id = ?', (session_id,))
        session_exists = c.fetchone()
        
        if not session_exists:
            return jsonify({'error': 'Session not found'}), 404
            
        return jsonify({'message': 'Joined session successfully'}), 200

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.get_json()
    full_name = data.get('fullName')
    email = data.get('email')
    password = data.get('password')

    if not full_name or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            password_hash = generate_password_hash(password)
            c.execute('INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
                     (full_name, email, password_hash))
            conn.commit()
            return jsonify({'message': 'Registration successful'}), 201
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Email already registered'}), 409

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('username')
    password = data.get('password')
    remember = data.get('remember', False)

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id, full_name, password_hash FROM users WHERE email = ?', (email,))
        user = c.fetchone()

        if not user or not check_password_hash(user[2], password):
            return jsonify({'error': 'Invalid email or password'}), 401

        session['user_id'] = user[0]
        session['full_name'] = user[1]
        if remember:
            session.permanent = True
        else:
            session.permanent = False

        return jsonify({'message': 'Login successful'}), 200

@app.route('/api/auth/forgot-password', methods=['POST'])
def api_forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = c.fetchone()

        if not user:
            return jsonify({'error': 'Email not found'}), 404

        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=1)

        c.execute('INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
                 (email, token, expires_at))
        conn.commit()

    if send_reset_email(email, token):
        return jsonify({'message': 'Password reset link sent'}), 200
    else:
        return jsonify({'error': 'Failed to send reset email'}), 500

@app.route('/api/auth/reset-password', methods=['POST'])
def api_reset_password():
    data = request.get_json()
    token = data.get('token')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')

    if not token or not password or not confirm_password:
        return jsonify({'error': 'All fields are required'}), 400

    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT email, expires_at FROM password_resets WHERE token = ?', (token,))
        reset = c.fetchone()

        if not reset:
            return jsonify({'error': 'Invalid or expired token'}), 404

        email, expires_at = reset
        if datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S.%f') < datetime.now():
            c.execute('DELETE FROM password_resets WHERE token = ?', (token,))
            conn.commit()
            return jsonify({'error': 'Token expired'}), 410

        password_hash = generate_password_hash(password)
        c.execute('UPDATE users SET password_hash = ? WHERE email = ?', (password_hash, email))
        c.execute('DELETE FROM password_resets WHERE token = ?', (token,))
        conn.commit()

        return jsonify({'message': 'Password reset successful'}), 200

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/users/search', methods=['GET'])
def search_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    search_term = request.args.get('q', '').strip()
    if not search_term:
        return jsonify([])

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT id, full_name, email
            FROM users
            WHERE full_name LIKE ? OR email LIKE ?
            LIMIT 10
        ''', (f'%{search_term}%', f'%{search_term}%'))
        results = [{'id': row[0], 'name': row[1], 'email': row[2]} for row in c.fetchall()]
        return jsonify(results)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/profile/<int:user_id>')
def get_user_profile(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT id, full_name, email, created_at
            FROM users
            WHERE id = ?
        ''', (user_id,))
        user = c.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        # Example fields; in production, fetch these from DB or user profile
        return jsonify({
            'id': user[0],
            'name': user[1],
            'email': user[2],
            'memberSince': user[3],
            'jobTitle': 'Software Engineer',
            'company': 'Tech Corp',
            'location': 'San Francisco',
            'linkedIn': 'https://linkedin.com/in/johndoe'
        })

@app.route('/api/network/request-connection', methods=['POST'])
def request_connection():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    target_user_id = data.get('targetUserId')
    if not target_user_id:
        return jsonify({'error': 'Target user ID required'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            c.execute('''
                INSERT INTO connection_requests (sender_id, receiver_id, status, created_at)
                VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)
            ''', (session['user_id'], target_user_id))
            conn.commit()
            return jsonify({'message': 'Connection request sent'}), 200
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Request already exists'}), 409

@app.route('/api/network/connection-status')
def connection_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    target_user_id = request.args.get('targetUserId')
    if not target_user_id:
        return jsonify({'error': 'Target user ID required'}), 400

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Check if already connected
        c.execute('''
            SELECT 1 FROM connections
            WHERE (user1_id = ? AND user2_id = ?)
            OR (user1_id = ? AND user2_id = ?)
        ''', (session['user_id'], target_user_id, target_user_id, session['user_id']))
        if c.fetchone():
            return jsonify({'status': 'connected'})
        # Check if pending request
        c.execute('''
            SELECT 1 FROM connection_requests
            WHERE sender_id = ? AND receiver_id = ? AND status = 'pending'
        ''', (session['user_id'], target_user_id))
        if c.fetchone():
            return jsonify({'status': 'pending'})
        return jsonify({'status': 'none'})

if __name__ == '__main__':
    app.run(debug=True)
