try:
    import os
    import secrets
    import smtplib
    from email.mime.text import MIMEText
    from datetime import datetime, timedelta
    from flask import Flask, render_template, request, jsonify, session, redirect, url_for
    import sqlite3
    from werkzeug.security import generate_password_hash, check_password_hash
    from flask_cors import CORS
except ImportError as e:
    print(f"Import error: {e}. Please ensure all dependencies are installed with 'pip install flask werkzeug flask-cors'.")
    exit(1)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app, supports_credentials=True)

# Database setup
DB_PATH = "conference.db"

def init_db():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    job_title TEXT NOT NULL,
                    company TEXT NOT NULL,
                    location TEXT NOT NULL,
                    linked_in TEXT,
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
                    duration INTEGER NOT NULL,
                    creator_id INTEGER NOT NULL,
                    max_participants INTEGER,
                    FOREIGN KEY (creator_id) REFERENCES users(id)
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS session_participants (
                    session_id TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    role TEXT NOT NULL DEFAULT 'attendee',
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (session_id, user_id),
                    FOREIGN KEY (session_id) REFERENCES sessions(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS session_questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    question TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
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
                    FOREIGN KEY (receiver_id) REFERENCES users(id),
                    CHECK (sender_id != receiver_id)
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS user_settings (
                    user_id INTEGER PRIMARY KEY,
                    dark_mode BOOLEAN DEFAULT 0,
                    email_notifications BOOLEAN DEFAULT 1,
                    session_reminders BOOLEAN DEFAULT 1,
                    new_messages BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            conn.commit()
            print("Database initialized successfully")
    except sqlite3.Error as e:
        print(f"Failed to initialize database: {e}")
        raise

# Initialize database
try:
    init_db()
except sqlite3.Error as e:
    print(f"Database initialization failed: {e}")
    exit(1)

# Email configuration
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'your_email@gmail.com',
    'sender_password': 'your_app_password'
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
    return render_template('landing.html')

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
    user_id = request.args.get('userId')
    if not user_id:
        return redirect(url_for('networking'))
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

@app.route('/live-session/<session_id>')
def live_session(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT full_name, email FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if not user:
            return redirect(url_for('login'))
        full_name, email = user
        c.execute('SELECT title FROM sessions WHERE id = ?', (session_id,))
        session_data = c.fetchone()
        if not session_data:
            return redirect(url_for('sessions'))
    return render_template('live-session.html', csrf_token=secrets.token_hex(16), 
                         full_name=full_name, email=email, session_id=session_id, 
                         session_title=session_data[0])

@app.route('/active-session')
def active_session():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT full_name, email FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if not user:
            return redirect(url_for('login'))
        full_name, email = user
    return render_template('active-session.html', csrf_token=secrets.token_hex(16), full_name=full_name, email=email)

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
    return render_template('settings.html', csrf_token=secrets.token_hex(16), full_name=full_name, email=email, session=session)

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

@app.route('/api/settings', methods=['GET'])
def api_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT dark_mode, email_notifications, session_reminders, new_messages FROM user_settings WHERE user_id = ?', (session['user_id'],))
        settings = c.fetchone()
        if not settings:
            c.execute('''
                INSERT OR IGNORE INTO user_settings (user_id, dark_mode, email_notifications, session_reminders, new_messages)
                VALUES (?, 0, 1, 1, 1)
            ''', (session['user_id'],))
            conn.commit()
            return jsonify({
                'darkMode': False,
                'emailNotifications': True,
                'sessionReminders': True,
                'newMessages': True
            }), 200
        return jsonify({
            'darkMode': bool(settings[0]),
            'emailNotifications': bool(settings[1]),
            'sessionReminders': bool(settings[2]),
            'newMessages': bool(settings[3])
        }), 200

@app.route('/api/settings/profile', methods=['PUT'])
def api_settings_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    full_name = data.get('fullName')
    email = data.get('email')
    job_title = data.get('jobTitle')
    company = data.get('company')
    location = data.get('location')
    linked_in = data.get('linkedIn')

    if not all([full_name, email, job_title, company, location]):
        return jsonify({'error': 'All required fields must be provided'}), 400

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            c.execute('''
                UPDATE users
                SET full_name = ?, email = ?, job_title = ?, company = ?, location = ?, linked_in = ?
                WHERE id = ?
            ''', (full_name, email, job_title, company, location, linked_in, session['user_id']))
            if c.rowcount == 0:
                return jsonify({'error': 'User not found'}), 404
            conn.commit()
            session['full_name'] = full_name
            return jsonify({'message': 'Profile updated successfully'}), 200
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Email already in use by another user'}), 409

@app.route('/api/settings/password', methods=['PUT'])
def api_settings_password():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    confirm_password = data.get('confirmPassword')

    if not current_password:
        return jsonify({'error': 'Current password is required'}), 400
    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match'}), 400
    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        if not check_password_hash(user[0], current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401

        new_password_hash = generate_password_hash(new_password)
        c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, session['user_id']))
        conn.commit()
        return jsonify({'message': 'Password updated successfully'}), 200

@app.route('/api/settings/theme', methods=['PUT'])
def api_settings_theme():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    dark_mode = data.get('darkMode', False)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO user_settings (user_id, dark_mode, email_notifications, session_reminders, new_messages)
            VALUES (?, ?, COALESCE((SELECT email_notifications FROM user_settings WHERE user_id = ?), 1),
                   COALESCE((SELECT session_reminders FROM user_settings WHERE user_id = ?), 1),
                   COALESCE((SELECT new_messages FROM user_settings WHERE user_id = ?), 1))
        ''', (session['user_id'], 1 if dark_mode else 0, session['user_id'], session['user_id'], session['user_id']))
        conn.commit()
        return jsonify({'message': 'Theme updated successfully'}), 200

@app.route('/api/settings/notifications', methods=['PUT'])
def api_settings_notifications():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    email_notifications = data.get('emailNotifications', True)
    session_reminders = data.get('sessionReminders', True)
    new_messages = data.get('newMessages', True)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO user_settings (user_id, dark_mode, email_notifications, session_reminders, new_messages)
            VALUES (?, COALESCE((SELECT dark_mode FROM user_settings WHERE user_id = ?), 0), ?, ?, ?)
        ''', (session['user_id'], session['user_id'], 1 if email_notifications else 0,
              1 if session_reminders else 0, 1 if new_messages else 0))
        conn.commit()
        return jsonify({'message': 'Notification preferences updated successfully'}), 200

@app.route('/api/sessions', methods=['GET', 'POST'])
def api_sessions():
    if request.method == 'POST':
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        date = data.get('date')
        type_ = data.get('type', 'virtual')
        duration = data.get('duration')
        max_participants = data.get('maxParticipants')
        if not all([title, date, duration]):
            return jsonify({'error': 'Missing required fields'}), 400
        session_id = secrets.token_hex(16)
        try:
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO sessions (id, title, description, date, type, duration, creator_id, max_participants)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (session_id, title, description, date, type_, duration, session['user_id'], max_participants))
                c.execute('''
                    INSERT INTO session_participants (session_id, user_id, role)
                    VALUES (?, ?, ?)
                ''', (session_id, session['user_id'], 'host'))
                conn.commit()
            return jsonify({'message': 'Session created', 'sessionId': session_id}), 201
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        recent = request.args.get('recent', default='false', type=str).lower() == 'true'
        search = request.args.get('search', '')
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            query = '''
                SELECT s.id, s.title, s.description, s.date, s.type, s.duration, s.max_participants,
                       u.full_name as creator_name
                FROM sessions s
                JOIN users u ON s.creator_id = u.id
                WHERE s.title LIKE ?
            '''
            params = [f'%{search}%']
            if recent:
                query += ' ORDER BY s.date DESC LIMIT 10'
            else:
                query += ' ORDER BY s.date ASC'
            c.execute(query, params)
            sessions = c.fetchall()
            return jsonify([
                {
                    'id': s[0],
                    'title': s[1],
                    'description': s[2],
                    'date': s[3],
                    'type': s[4],
                    'duration': s[5],
                    'maxParticipants': s[6],
                    'creatorName': s[7]
                } for s in sessions
            ]), 200

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
def api_delete_session(session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # First check if the user is the creator of this session
        c.execute('SELECT creator_id FROM sessions WHERE id = ?', (session_id,))
        session_data = c.fetchone()
        if not session_data:
            return jsonify({'error': 'Session not found'}), 404
        if session_data[0] != session['user_id']:
            return jsonify({'error': 'Only session creator can delete sessions'}), 403
        
        # Delete the session and all related data
        c.execute('DELETE FROM session_participants WHERE session_id = ?', (session_id,))
        c.execute('DELETE FROM session_questions WHERE session_id = ?', (session_id,))
        c.execute('DELETE FROM sessions WHERE id = ?', (session_id,))
        conn.commit()
        
    return jsonify({'message': 'Session deleted successfully'}), 200

@app.route('/api/sessions/<session_id>/join', methods=['POST'])
def api_join_session(session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id, max_participants FROM sessions WHERE id = ?', (session_id,))
        session_data = c.fetchone()
        if not session_data:
            return jsonify({'error': 'Session not found'}), 404
        c.execute('SELECT COUNT(*) FROM session_participants WHERE session_id = ?', (session_id,))
        participant_count = c.fetchone()[0]
        if session_data[1] and participant_count >= session_data[1]:
            return jsonify({'error': 'Session is full'}), 409
        try:
            c.execute('''
                INSERT INTO session_participants (session_id, user_id, role)
                VALUES (?, ?, 'attendee')
            ''', (session_id, session['user_id']))
            conn.commit()
            return jsonify({'message': 'Joined session successfully', 'sessionId': session_id}), 200
        except sqlite3.IntegrityError:
            return jsonify({'message': 'Already joined'}), 200

@app.route('/api/sessions/<session_id>/participants', methods=['GET'])
def api_session_participants(session_id):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM sessions WHERE id = ?', (session_id,))
        if not c.fetchone():
            return jsonify({'error': 'Session not found'}), 404
        c.execute('''
            SELECT u.id, u.full_name, u.email, sp.role
            FROM session_participants sp
            JOIN users u ON sp.user_id = u.id
            WHERE sp.session_id = ?
        ''', (session_id,))
        participants = c.fetchall()
        return jsonify([
            {
                'id': p[0],
                'name': p[1],
                'email': p[2],
                'role': p[3]
            } for p in participants
        ]), 200

@app.route('/api/sessions/<session_id>/questions', methods=['GET', 'POST'])
def api_session_questions(session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM sessions WHERE id = ?', (session_id,))
        if not c.fetchone():
            return jsonify({'error': 'Session not found'}), 404
        if request.method == 'POST':
            data = request.get_json()
            question = data.get('question')
            if not question:
                return jsonify({'error': 'Question required'}), 400
            c.execute('''
                INSERT INTO session_questions (session_id, user_id, question)
                VALUES (?, ?, ?)
            ''', (session_id, session['user_id'], question))
            conn.commit()
            return jsonify({'message': 'Question submitted'}), 201
        else:
            c.execute('''
                SELECT sq.id, sq.question, sq.created_at, u.full_name
                FROM session_questions sq
                JOIN users u ON sq.user_id = u.id
                WHERE sq.session_id = ?
                ORDER BY sq.created_at
            ''', (session_id,))
            questions = c.fetchall()
            return jsonify([
                {
                    'id': q[0],
                    'question': q[1],
                    'createdAt': q[2],
                    'askedBy': q[3]
                } for q in questions
            ]), 200

@app.route('/api/sessions/<session_id>/assign-role', methods=['POST'])
def api_assign_role(session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    user_id = data.get('userId')
    role = data.get('role')
    if not user_id or not role or role not in ['host', 'speaker', 'attendee']:
        return jsonify({'error': 'Invalid request'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT creator_id FROM sessions WHERE id = ?', (session_id,))
        session_data = c.fetchone()
        if not session_data:
            return jsonify({'error': 'Session not found'}), 404
        if session_data[0] != session['user_id']:
            return jsonify({'error': 'Only session creator can assign roles'}), 403
        c.execute('''
            INSERT OR REPLACE INTO session_participants (session_id, user_id, role)
            VALUES (?, ?, ?)
        ''', (session_id, user_id, role))
        conn.commit()
        return jsonify({'message': 'Role assigned successfully'}), 200

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.get_json()
    full_name = data.get('fullName')
    email = data.get('email')
    password = data.get('password')
    job_title = data.get('jobTitle', 'Unknown')
    company = data.get('company', 'Unknown')
    location = data.get('location', 'Unknown')
    linked_in = data.get('linkedIn', '')
    if not all([full_name, email, password, job_title, company, location]):
        return jsonify({'error': 'All required fields are required'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            password_hash = generate_password_hash(password)
            c.execute('''
                INSERT INTO users (full_name, email, password_hash, job_title, company, location, linked_in, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (full_name, email, password_hash, job_title, company, location, linked_in))
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
        session.permanent = True  # Always enable permanent sessions
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
            WHERE full_name LIKE ? OR email LIKE ? AND id != ?
            LIMIT 10
        ''', (f'%{search_term}%', f'%{search_term}%', session['user_id']))
        results = [{'id': row[0], 'name': row[1], 'email': row[2]} for row in c.fetchall()]
        return jsonify(results)

@app.route('/api/network/requests', methods=['GET'])
def get_connection_requests():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT cr.id, cr.sender_id, u.full_name, u.email, cr.status
            FROM connection_requests cr
            JOIN users u ON cr.sender_id = u.id
            WHERE cr.receiver_id = ? AND cr.status = 'pending'
            ORDER BY cr.created_at DESC
        ''', (session['user_id'],))
        requests = c.fetchall()
        return jsonify([
            {
                'requestId': r[0],
                'senderId': r[1],
                'senderName': r[2],
                'senderEmail': r[3],
                'status': r[4]
            } for r in requests
        ]), 200

@app.route('/api/network/connections', methods=['GET'])
def get_connections():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT 
                CASE 
                    WHEN cr.sender_id = ? THEN cr.receiver_id 
                    ELSE cr.sender_id 
                END as connected_user_id,
                u.full_name, 
                u.email
            FROM connection_requests cr
            JOIN users u 
                ON (cr.sender_id = ? AND u.id = cr.receiver_id) 
                OR (cr.receiver_id = ? AND u.id = cr.sender_id)
            WHERE cr.status = 'accepted'
            ORDER BY cr.created_at DESC
        ''', (session['user_id'], session['user_id'], session['user_id']))
        connections = c.fetchall()
        return jsonify([
            {
                'id': c[0],
                'name': c[1],
                'email': c[2]
            } for c in connections
        ]), 200

@app.route('/api/network/update-connection', methods=['POST'])
def update_connection():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    request_id = data.get('requestId')
    action = data.get('action')
    if not request_id or not action or action not in ['accept', 'reject']:
        return jsonify({'error': 'Invalid request'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT sender_id, receiver_id, status
            FROM connection_requests
            WHERE id = ? AND receiver_id = ?
        ''', (request_id, session['user_id']))
        request_data = c.fetchone()
        if not request_data:
            return jsonify({'error': 'Request not found or unauthorized'}), 404
        if request_data[2] != 'pending':
            return jsonify({'error': 'Request already processed'}), 409
        new_status = 'accepted' if action == 'accept' else 'rejected'
        c.execute('''
            UPDATE connection_requests
            SET status = ?, created_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (new_status, request_id))
        conn.commit()
        return jsonify({'message': f'Connection request {action}ed'}), 200

@app.route('/api/network/request-connection', methods=['POST'])
def request_connection():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    target_user_id = data.get('targetUserId')
    if not target_user_id:
        return jsonify({'error': 'Target user ID required'}), 400
    sender_id = session['user_id']
    if str(target_user_id) == str(sender_id):
        return jsonify({'error': 'Cannot send a connection request to yourself'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE id = ?', (sender_id,))
        if not c.fetchone():
            return jsonify({'error': 'Sender user not found'}), 404
        c.execute('SELECT id FROM users WHERE id = ?', (target_user_id,))
        if not c.fetchone():
            return jsonify({'error': 'Target user not found'}), 404
        try:
            c.execute('''
                INSERT INTO connection_requests (sender_id, receiver_id, status, created_at)
                VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)
            ''', (sender_id, target_user_id))
            conn.commit()
            return jsonify({'message': 'Connection request sent'}), 200
        except sqlite3.IntegrityError as e:
            if "CHECK constraint failed" in str(e):
                return jsonify({'error': 'Cannot send a connection request to yourself'}), 400
            c.execute('''
                SELECT status FROM connection_requests 
                WHERE sender_id = ? AND receiver_id = ?
            ''', (sender_id, target_user_id))
            existing = c.fetchone()
            if existing and existing[0] in ['pending', 'accepted', 'rejected']:
                return jsonify({'error': f'Request already exists with status: {existing[0]}'}), 409
            return jsonify({'error': 'Failed to send request due to a database constraint'}), 500

@app.route('/api/network/connection-status')
def connection_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    target_user_id = request.args.get('targetUserId')
    if not target_user_id:
        return jsonify({'error': 'Target user ID required'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT status
            FROM connection_requests
            WHERE (sender_id = ? AND receiver_id = ?)
            OR (sender_id = ? AND receiver_id = ?)
        ''', (session['user_id'], target_user_id, target_user_id, session['user_id']))
        result = c.fetchone()
        if result:
            return jsonify({'status': result[0]})
        return jsonify({'status': 'none'})

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
            SELECT id, full_name, email, created_at, 
                   COALESCE(job_title, 'Not specified') AS job_title,
                   COALESCE(company, 'Not specified') AS company,
                   COALESCE(location, 'Not specified') AS location,
                   COALESCE(linked_in, '') AS linked_in
            FROM users
            WHERE id = ?
        ''', (user_id,))
        user = c.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({
            'id': user[0],
            'name': user[1],
            'email': user[2],
            'memberSince': user[3],
            'jobTitle': user[4],
            'company': user[5],
            'location': user[6],
            'linkedIn': user[7]
        })

@app.route('/app')
def app_home():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
