from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import jwt_required, get_jwt_identity
from functools import wraps

socketio = SocketIO()

def authenticated_only(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not get_jwt_identity():
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped
 
@socketio.on('connect')
@authenticated_only
def handle_connect():
    user_id = get_jwt_identity()
    join_room(f'user_{user_id}')
    emit('connection_established', {'status': 'connected'})

@socketio.on('subscribe_sessions')
@authenticated_only
def handle_session_subscription():
    join_room('sessions_updates')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

def broadcast_session_update(session_data):
    emit('session_update', session_data, room='sessions_updates', namespace='/')
