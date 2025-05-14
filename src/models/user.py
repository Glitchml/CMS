from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
  
db = SQLAlchemy()
 
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    # Add profile fields
    job_title = db.Column(db.String(100))
    company = db.Column(db.String(100))
    location = db.Column(db.String(100))
    bio = db.Column(db.Text)
    linkedin_url = db.Column(db.String(200))
    avatar_url = db.Column(db.String(200))

    # Add settings fields
    theme_preference = db.Column(db.String(20), default='light')
    email_notifications = db.Column(db.Boolean, default=True)
    session_reminders = db.Column(db.Boolean, default=True)
    message_notifications = db.Column(db.Boolean, default=True)

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """Simplified user serialization"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'profile': {
                'job_title': self.job_title,
                'company': self.company,
                'location': self.location,
                'avatar_url': self.avatar_url
            },
            'settings': {
                'theme': self.theme_preference,
                'notifications': {
                    'email': self.email_notifications,
                    'sessions': self.session_reminders,
                    'messages': self.message_notifications
                }
            }
        }

    def update_profile(self, data):
        for key, value in data.items():
            if hasattr(self, key) and key not in ['id', 'password_hash']:
                setattr(self, key, value)
        return True

    def update_settings(self, settings_data):
        """Simplified settings update"""
        for key, value in settings_data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return True

    def change_password(self, current_password, new_password):
        """Change user password"""
        if self.check_password(current_password):
            self.set_password(new_password)
            return True
        return False

# Add Session and UserSession models
class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # in minutes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add new fields
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    status = db.Column(db.String(20), default='scheduled')  # scheduled, active, ended
    max_participants = db.Column(db.Integer, default=100)
    tags = db.Column(db.String(200))
    
    # Add relationship with creator
    creator = db.relationship('User', foreign_keys=[creator_id])
    
    def assign_role(self, user, role):
        if role not in ['host', 'speaker', 'attendee']:
            return False
            
        participation = UserSessionRole.query.filter_by(
            user_id=user.id,
            session_id=self.id
        ).first()
        
        if participation:
            participation.role = role
        else:
            participation = UserSessionRole(user=user, session=self, role=role)
            db.session.add(participation)
        return True

    def get_participant_role(self, user_id):
        participation = UserSessionRole.query.filter_by(
            user_id=user_id,
            session_id=self.id
        ).first()
        return participation.role if participation else None

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'startTime': self.start_time.isoformat(),
            'duration': self.duration,
            'participantCount': self.participants.count(),
            'creator': self.creator.username,
            'status': self.status,
            'maxParticipants': self.max_participants,
            'tags': self.tags.split(',') if self.tags else [],
            'roles': {
                'host': [p.user.username for p in self.roles if p.role == 'host'],
                'speakers': [p.user.username for p in self.roles if p.role == 'speaker']
            }
        }

# Add UserSessionRole model for role management
class UserSessionRole(db.Model):
    __tablename__ = 'user_session_roles'
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('sessions.id'), primary_key=True)
    role = db.Column(db.String(20), nullable=False)  # host, speaker, attendee
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User')
    session = db.relationship('Session', backref=db.backref('roles', lazy='dynamic'))

# Association table for User-Session many-to-many relationship
user_sessions = db.Table('user_sessions',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('session_id', db.Integer, db.ForeignKey('sessions.id'), primary_key=True),
    db.Column('joined_at', db.DateTime, default=datetime.utcnow)
)

# Add Connection Request model
class ConnectionRequest(db.Model):
    __tablename__ = 'connection_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    
    def to_dict(self):
        return {
            'id': self.id,
            'sender': self.sender.to_dict(),
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }

# Add Connections association table
connections = db.Table('connections',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('connected_user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('connected_at', db.DateTime, default=datetime.utcnow)
)

# Add blocked users association table
blocked_users = db.Table('blocked_users',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('blocked_user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('blocked_at', db.DateTime, default=datetime.utcnow)
)