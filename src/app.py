from flask import Flask, request, jsonify, render_template, make_response, redirect
from config import Config  # Changed from src.config
from models.user import db, User  # Changed from src.models.user
from src.models.session import Session  # Add this import
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
) 
from flask_cors import CORS  # Add this import at the top
from functools import wraps
from datetime import timedelta, datetime

def dashboard_token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # First try to get token from Authorization header
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                verify_jwt_in_request()
                return f(*args, **kwargs)
            
            # Then try to get token from query params
            token = request.args.get('token')
            if token:
                request.headers['Authorization'] = f'Bearer {token}'
                verify_jwt_in_request()
                return f(*args, **kwargs)
            
            return jsonify({"error": "Token is missing"}), 401
            
        except Exception as e:
            return jsonify({"error": str(e)}), 401
    
    return decorated_function

# Add this after the existing decorators
def handle_db_operation(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            result = f(*args, **kwargs)
            db.session.commit()
            return result
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    return decorated_function

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    jwt = JWTManager(app)

    app.url_map.strict_slashes = False

    # Add CORS support with more specific configuration
    CORS(app, resources={
        r"/api/*": {"origins": "*"},
        r"/dashboard/*": {"origins": "*"},
        r"/login/*": {"origins": "*"},
        r"/": {"origins": "*"}
    }, supports_credentials=True)

    # Page Routes
    @app.route('/')
    def index():
        return render_template('landing.html')

    @app.route('/login/', methods=['GET', 'POST'])
    def login_page():
        return render_template('login.html')


    @app.route('/signup')
    def signup_page():
        return render_template('signup.html')

    @app.route('/dashboard', methods=['GET', 'POST'])
    def dashboard():
        # Get token from cookie
        token = request.cookies.get('access_token_cookie')
        
        if not token:
            return redirect('/login')
            
        try:
            # Verify token
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            return render_template('dashboard.html', user=user.to_dict())
        except:
            return redirect('/login')

    @app.route('/profile/', methods=['GET', 'POST'])
    @jwt_required()
    def profile():
        return render_template('profile.html')

    @app.route('/settings/', methods=['GET', 'POST'])
    @jwt_required()
    def settings():
        return render_template('settings.html')

    @app.route('/networking/', methods=['GET', 'POST'])
    @jwt_required()
    def networking():
        return render_template('networking-page.html')

    @app.route('/forgot-password/', methods=['GET', 'POST'])
    def forgot_password_page():
        return render_template('forgot-password.html')

    @app.route('/sessions/', methods=['GET', 'POST'])
    @jwt_required()
    def sessions():
        return render_template('sessions.html')

    # Create tables within app context
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

    # Store revoked tokens in memory
    revoked_tokens = set()

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        return jti in revoked_tokens

    @app.route('/api/auth/register', methods=['POST'])
    def register():
        data = request.get_json()
        required_fields = ['username', 'email', 'password']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing fields: {", ".join(missing_fields)}'}), 400

        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 409
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 409

        user = User(
            username=data['username'],
            email=data['email']
        )
        user.set_password(data['password'])

        try:
            db.session.add(user)
            db.session.commit()
            return jsonify({
                'message': 'User created successfully',
                'user': user.to_dict()
            }), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Failed to create user'}), 500

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.get_json()
        if not all(k in data for k in ['username', 'password']):
            return jsonify({'error': 'Missing username or password'}), 400

        user = User.query.filter_by(username=data['username']).first()
        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid username or password'}), 401

        access_token = create_access_token(identity=user.id)
        
        # Create response with cookie
        response = make_response(jsonify({
            'message': 'Login successful',
            'user': user.to_dict()
        }))
        
        # Set JWT as HTTP-only cookie
        response.set_cookie(
            'access_token_cookie',
            access_token,
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=3600  # 1 hour
        )
        
        return response

    @app.route('/api/protected', methods=['GET'])
    @jwt_required()
    def protected():
        current_user_id = get_jwt_identity()
        print(f"Current User ID: {current_user_id}")  # Debug print
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'message': 'Access granted to protected route',
            'user': user.to_dict()
        })

    @app.route('/api/auth/refresh', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh():
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return jsonify({'access_token': access_token}), 200

    @app.route('/api/auth/logout', methods=['POST'])
    @jwt_required()
    def logout():
        jti = get_jwt()["jti"]
        revoked_tokens.add(jti)
        return jsonify({"message": "Successfully logged out"}), 200

    # Dashboard API Routes
    @app.route('/api/user/<int:user_id>')
    @jwt_required()
    def get_user_profile(user_id):
        current_user_id = get_jwt_identity()
        if current_user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        user = User.query.get_or_404(user_id)
        return jsonify(user.to_dict())

    @app.route('/api/sessions')
    @jwt_required()
    def get_sessions():
        user_id = get_jwt_identity()
        recent = request.args.get('recent', type=bool, default=False)
        
        query = Session.query
        if recent:
            query = query.filter(Session.start_time >= datetime.utcnow())
        
        sessions = query.order_by(Session.start_time).limit(10).all()
        return jsonify([session.to_dict() for session in sessions])

    @app.route('/api/sessions/<int:session_id>')
    @jwt_required()
    def get_session(session_id):
        session = Session.query.get_or_404(session_id)
        return jsonify(session.to_dict())

    @app.route('/api/sessions/<int:session_id>/join', methods=['POST'])
    @jwt_required()
    def join_session(session_id):
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        session = Session.query.get_or_404(session_id)
        
        if user.join_session(session):
            db.session.commit()
            return jsonify({'message': 'Joined session successfully'})
        
        return jsonify({'error': 'Already in session'}), 400

    # Session Management API Routes
    @app.route('/api/sessions', methods=['POST'])
    @jwt_required()
    def create_session():
        data = request.get_json()
        user_id = get_jwt_identity()
        
        required_fields = ['title', 'description', 'startTime', 'duration']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        try:
            session = Session(
                title=data['title'],
                description=data['description'],
                start_time=datetime.fromisoformat(data['startTime'].replace('Z', '+00:00')),
                duration=data['duration'],
                creator_id=user_id,
                max_participants=data.get('maxParticipants', 100),
                tags=','.join(data.get('tags', []))
            )
            
            db.session.add(session)
            session.assign_role(User.query.get(user_id), 'host')
            db.session.commit()
            
            return jsonify({
                'message': 'Session created successfully',
                'session': session.to_dict()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/sessions/schedule', methods=['POST'])
    @jwt_required()
    def schedule_session():
        data = request.get_json()
        user_id = get_jwt_identity()
        
        session = Session.query.get_or_404(data['sessionId'])
        if session.creator_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        try:
            session.start_time = datetime.fromisoformat(data['scheduledTime'].replace('Z', '+00:00'))
            session.status = 'scheduled'
            
            # Add invited users
            for invitee_id in data.get('invitees', []):
                invitee = User.query.get(invitee_id)
                if invitee:
                    session.assign_role(invitee, 'attendee')
                    
            db.session.commit()
            return jsonify({'message': 'Session scheduled successfully'})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/sessions/assign-role', methods=['POST'])
    @jwt_required()
    def assign_session_role():
        data = request.get_json()
        user_id = get_jwt_identity()
        
        session = Session.query.get_or_404(data['sessionId'])
        if session.get_participant_role(user_id) != 'host':
            return jsonify({'error': 'Only hosts can assign roles'}), 403
            
        try:
            target_user = User.query.get_or_404(data['userId'])
            if session.assign_role(target_user, data['role']):
                db.session.commit()
                return jsonify({'message': 'Role assigned successfully'})
            return jsonify({'error': 'Invalid role'}), 400
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/users')
    @jwt_required()
    def search_session_users():
        query = request.args.get('search', '')
        users = User.search_users(query, get_jwt_identity())
        return jsonify([{
            'id': user.id,
            'name': user.username,
            'email': user.email
        } for user in users])

    # Networking API Routes
    @app.route('/api/network/users')
    @jwt_required()
    def get_network_users():
        user_id = get_jwt_identity()
        users = User.query.filter(User.id != user_id).all()
        return jsonify([user.to_dict() for user in users])

    @app.route('/api/network/requests')
    @jwt_required()
    def get_connection_requests():
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        return jsonify([req.to_dict() for req in user.pending_requests])

    @app.route('/api/network/connect/<int:target_id>', methods=['POST'])
    @jwt_required()
    def send_connection_request(target_id):
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        target = User.query.get_or_404(target_id)
        
        if user.send_connection_request(target):
            db.session.commit()
            return jsonify({'message': 'Connection request sent'})
        return jsonify({'error': 'Request already sent'}), 400

    @app.route('/api/network/accept/<int:request_id>', methods=['POST'])
    @jwt_required()
    def accept_connection(request_id):
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        request = ConnectionRequest.query.get_or_404(request_id)
        
        if request.target_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        if user.accept_connection_request(request):
            db.session.commit()
            return jsonify({'message': 'Connection accepted'})
        return jsonify({'error': 'Invalid request'}), 400

    # Additional Networking API Routes
    @app.route('/api/network/decline/<int:request_id>', methods=['POST'])
    @jwt_required()
    def decline_connection(request_id):
        user_id = get_jwt_identity()
        request = ConnectionRequest.query.get_or_404(request_id)
        
        if request.target_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        request.status = 'declined'
        db.session.commit()
        return jsonify({'message': 'Connection request declined'})

    @app.route('/api/network/block/<int:user_id>', methods=['POST'])
    @jwt_required()
    def block_user(user_id):
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(current_user_id)
        target = User.query.get_or_404(user_id)
        
        if user.block_user(target):
            db.session.commit()
            return jsonify({'message': 'User blocked successfully'})
        return jsonify({'error': 'User already blocked'}), 400

    @app.route('/api/network/unblock/<int:user_id>', methods=['DELETE'])
    @jwt_required()
    def unblock_user(user_id):
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(current_user_id)
        target = User.query.get_or_404(user_id)
        
        if user.unblock_user(target):
            db.session.commit()
            return jsonify({'message': 'User unblocked successfully'})
        return jsonify({'error': 'User not blocked'}), 400

    @app.route('/api/network/blocked')
    @jwt_required()
    def get_blocked_users():
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        return jsonify([blocked.to_dict() for blocked in user.blocked_users])

    @app.route('/api/network/search')
    @jwt_required()
    def search_users():
        query = request.args.get('q', '')
        if len(query) < 2:
            return jsonify({'error': 'Search query too short'}), 400
            
        current_user_id = get_jwt_identity()
        users = User.search_users(query, current_user_id)
        return jsonify([user.to_dict() for user in users])

    # Profile Management API Routes
    @app.route('/api/profile/<int:user_id>')
    @jwt_required()
    def get_profile(user_id):
        user = User.query.get_or_404(user_id)
        return jsonify(user.to_dict())

    @app.route('/api/profile/<int:user_id>', methods=['PUT'])
    @jwt_required()
    def update_profile(user_id):
        current_user_id = get_jwt_identity()
        if current_user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        try:
            user.update_profile(data)
            db.session.commit()
            return jsonify({
                'message': 'Profile updated successfully',
                'user': user.to_dict()
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/profile/avatar', methods=['POST'])
    @jwt_required()
    def upload_avatar():
        if 'avatar' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['avatar']
        if not file.filename:
            return jsonify({'error': 'No file selected'}), 400
            
        try:
            # Save file and get URL
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Update user's avatar URL
            user_id = get_jwt_identity()
            user = User.query.get_or_404(user_id)
            user.avatar_url = f'/uploads/{filename}'
            db.session.commit()
            
            return jsonify({
                'message': 'Avatar uploaded successfully',
                'avatarUrl': user.avatar_url
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/profile/stats')
    @jwt_required()
    def get_user_stats():
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        return jsonify(user.get_stats())

    @app.route('/api/profile/sessions')
    @jwt_required()
    def get_user_sessions():
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        
        session_type = request.args.get('type', 'upcoming')
        now = datetime.utcnow()
        
        if session_type == 'upcoming':
            sessions = [s for s in user.sessions if s.start_time > now]
        else:  # history
            sessions = [s for s in user.sessions if s.start_time <= now]
            
        return jsonify([{
            'id': s.id,
            'title': s.title,
            'date': s.start_time.isoformat(),
            'type': UserSessionRole.query.filter_by(
                user_id=user_id,
                session_id=s.id
            ).first().role,
            'status': s.status
        } for s in sessions])

    # Settings Management API Routes
    @app.route('/api/settings/<int:user_id>')
    @jwt_required()
    def get_settings(user_id):
        current_user_id = get_jwt_identity()
        if current_user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        user = User.query.get_or_404(user_id)
        return jsonify({
            'profile': user.to_dict(),
            'settings': {
                'theme': user.theme_preference,
                'notifications': {
                    'email': user.email_notifications,
                    'sessions': user.session_reminders,
                    'messages': user.message_notifications
                }
            }
        })

    @app.route('/api/settings/profile', methods=['PUT'])
    @jwt_required()
    @handle_db_operation
    def update_settings_profile():
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        user.update_profile(data)
        return jsonify({
            'message': 'Profile settings updated successfully',
            'user': user.to_dict()
        })

    @app.route('/api/settings/password', methods=['PUT'])
    @jwt_required()
    def change_password():
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        if not all(k in data for k in ['currentPassword', 'newPassword']):
            return jsonify({'error': 'Missing required fields'}), 400
            
        try:
            if user.change_password(data['currentPassword'], data['newPassword']):
                db.session.commit()
                return jsonify({'message': 'Password changed successfully'})
            return jsonify({'error': 'Current password is incorrect'}), 400
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/settings/notifications', methods=['PUT'])
    @jwt_required()
    def update_notification_settings():
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        try:
            user.update_settings({
                'email_notifications': data.get('email', True),
                'session_reminders': data.get('sessions', True),
                'message_notifications': data.get('messages', True)
            })
            db.session.commit()
            return jsonify({'message': 'Notification settings updated successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/settings/theme', methods=['PUT'])
    @jwt_required()
    def update_theme_settings():
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        try:
            user.update_settings({
                'theme_preference': data.get('darkMode', False) and 'dark' or 'light'
            })
            db.session.commit()
            return jsonify({'message': 'Theme settings updated successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    # Add WebSocket support for real-time updates
    from flask_socketio import SocketIO, emit, join_room, leave_room
    socketio = SocketIO(app, cors_allowed_origins="*")

    @socketio.on('connect')
    @jwt_required()
    def handle_connect():
        user_id = get_jwt_identity()
        join_room(f'user_{user_id}')
        
    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')

    def notify_connection_update(user_id, data):
        emit('connection_update', data, room=f'user_{user_id}')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)