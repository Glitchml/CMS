from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models.user import User, Session, db
from ..websocket import broadcast_session_update
from datetime import datetime

dashboard = Blueprint('dashboard', __name__)

@dashboard.route('/api/user/<int:user_id>')
@jwt_required()
def get_user_profile(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

@dashboard.route('/api/sessions')
@jwt_required()
def get_sessions():
    # Get query parameters
    recent = request.args.get('recent', type=bool, default=False)
    
    query = Session.query
    
    if recent:
        query = query.filter(Session.start_time >= datetime.utcnow())
    
    sessions = query.order_by(Session.start_time).limit(10).all()
    return jsonify([session.to_dict() for session in sessions])

@dashboard.route('/api/sessions/<int:session_id>')
@jwt_required()
def get_session(session_id):
    session = Session.query.get_or_404(session_id)
    return jsonify(session.to_dict())

@dashboard.route('/api/sessions/<int:session_id>/join', methods=['POST'])
@jwt_required()
def join_session(session_id):
    current_user_id = get_jwt_identity()
    user = User.query.get_or_404(current_user_id)
    session = Session.query.get_or_404(session_id)
    
    if user.join_session(session):
        db.session.commit()
        # Broadcast update via WebSocket
        broadcast_session_update({
            'type': 'participant_joined',
            'sessionId': session_id,
            'participant': user.to_dict()
        })
        return jsonify({'message': 'Joined session successfully'})
    
    return jsonify({'error': 'Already in session'}), 400
