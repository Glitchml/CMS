from flask import Flask, request, jsonify, render_template, make_response, redirect
from config import Config  # Changed from src.config
from models.user import db, User  # Changed from src.models.user
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
)
from flask_cors import CORS  # Add this import at the top
from functools import wraps
from datetime import timedelta

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

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)