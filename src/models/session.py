from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
 
db = SQLAlchemy()

class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # in minutes
    status = db.Column(db.String(20), default='scheduled')  # scheduled, active, ended
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Basic relationships
    creator = db.relationship('User', backref='created_sessions')
    participants = db.relationship('User', secondary='user_sessions',
                                 backref=db.backref('joined_sessions', lazy='dynamic'))

    def to_dict(self):
        """Minimal session serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'startTime': self.start_time.isoformat(),
            'duration': self.duration,
            'status': self.status,
            'creatorId': self.creator_id,
            'participantCount': len(self.participants)
        }

    def add_participant(self, user):
        """Add participant to session"""
        if user not in self.participants:
            self.participants.append(user)
            return True
        return False

    def remove_participant(self, user):
        """Remove participant from session"""
        if user in self.participants:
            self.participants.remove(user)
            return True
        return False

    def is_active(self):
        """Check if session is currently active"""
        now = datetime.utcnow()
        session_end = self.start_time + timedelta(minutes=self.duration)
        return self.start_time <= now <= session_end

# Simple association table for users and sessions
user_sessions = db.Table('user_sessions',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('session_id', db.Integer, db.ForeignKey('sessions.id'), primary_key=True),
    db.Column('joined_at', db.DateTime, default=datetime.utcnow)
)
