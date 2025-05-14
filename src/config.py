import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

class Config:
    # Instance path configuration
    INSTANCE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance')
    if not os.path.exists(INSTANCE_PATH):
        os.makedirs(INSTANCE_PATH)
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(INSTANCE_PATH, "database.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    
    # JWT and application secret keys
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    SECRET_KEY = os.getenv('SECRET_KEY')

    # JWT configuration
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)  # Simpler token lifetime
    
    # WebSocket configuration
    WS_ENABLED = True
    WS_PING_INTERVAL = 25
    WS_PING_TIMEOUT = 120
    
    # Session configuration
    SESSION_LIFETIME = timedelta(hours=2)
    MAX_PARTICIPANTS = 100

    # File upload configuration
    UPLOAD_FOLDER = os.path.join(INSTANCE_PATH, 'uploads')
    ALLOWED_EXTENSIONS = {'jpg', 'png'}  # Limit to common formats
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max file size for MVP