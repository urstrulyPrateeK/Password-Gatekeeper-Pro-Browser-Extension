"""
Password Gatekeeper Pro - API Routes
REST API endpoints for password sync and management
"""

from flask import Blueprint, request, jsonify, g

from .auth import require_auth, auth_service
from .database import db
from .models import PasswordEntry, SyncLog, PasswordStrengthChecker


# Create Blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')


# ==========================================
# Health Check
# ==========================================

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "Password Gatekeeper Pro API",
        "version": "1.0.0"
    })


# ==========================================
# Authentication Routes
# ==========================================

@api_bp.route('/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    if not data:
        return jsonify({
            "success": False,
            "error": "Request body required"
        }), 400
    
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({
            "success": False,
            "error": "Email and password required"
        }), 400
    
    result = auth_service.register(email, password)
    status_code = 201 if result['success'] else 400
    
    return jsonify(result), status_code


@api_bp.route('/auth/login', methods=['POST'])
def login():
    """Login and get access token"""
    data = request.get_json()
    
    if not data:
        return jsonify({
            "success": False,
            "error": "Request body required"
        }), 400
    
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({
            "success": False,
            "error": "Email and password required"
        }), 400
    
    result = auth_service.login(email, password)
    status_code = 200 if result['success'] else 401
    
    return jsonify(result), status_code


@api_bp.route('/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token"""
    data = request.get_json()
    
    if not data or 'refresh_token' not in data:
        return jsonify({
            "success": False,
            "error": "Refresh token required"
        }), 400
    
    result = auth_service.refresh_token(data['refresh_token'])
    status_code = 200 if result['success'] else 401
    
    return jsonify(result), status_code


@api_bp.route('/auth/me', methods=['GET'])
@require_auth
def get_current_user():
    """Get current user info"""
    return jsonify({
        "success": True,
        "user": g.user.to_dict(),
        "stats": db.get_user_stats(g.user_id)
    })


# ==========================================
# Password Routes
# ==========================================

@api_bp.route('/passwords', methods=['GET'])
@require_auth
def get_passwords():
    """Get all password entries for current user"""
    entries = db.get_password_entries(g.user_id)
    
    return jsonify({
        "success": True,
        "entries": [e.to_dict() for e in entries],
        "count": len(entries)
    })


@api_bp.route('/passwords', methods=['POST'])
@require_auth
def create_password():
    """Create a new password entry"""
    data = request.get_json()
    
    if not data or 'data' not in data:
        return jsonify({
            "success": False,
            "error": "Encrypted data required"
        }), 400
    
    entry = PasswordEntry(
        id=data.get('id'),  # Client can provide ID for sync
        user_id=g.user_id,
        encrypted_data=data['data']
    )
    
    if data.get('createdAt'):
        entry.created_at = data['createdAt']
    if data.get('updatedAt'):
        entry.updated_at = data['updatedAt']
    
    db.create_password_entry(entry)
    
    return jsonify({
        "success": True,
        "entry": entry.to_dict()
    }), 201


@api_bp.route('/passwords/<entry_id>', methods=['GET'])
@require_auth
def get_password(entry_id):
    """Get a specific password entry"""
    entry = db.get_password_entry(entry_id, g.user_id)
    
    if not entry:
        return jsonify({
            "success": False,
            "error": "Password entry not found"
        }), 404
    
    return jsonify({
        "success": True,
        "entry": entry.to_dict()
    })


@api_bp.route('/passwords/<entry_id>', methods=['PUT'])
@require_auth
def update_password(entry_id):
    """Update a password entry"""
    data = request.get_json()
    
    if not data or 'data' not in data:
        return jsonify({
            "success": False,
            "error": "Encrypted data required"
        }), 400
    
    entry = db.get_password_entry(entry_id, g.user_id)
    
    if not entry:
        return jsonify({
            "success": False,
            "error": "Password entry not found"
        }), 404
    
    entry.encrypted_data = data['data']
    
    if db.update_password_entry(entry):
        return jsonify({
            "success": True,
            "entry": entry.to_dict()
        })
    
    return jsonify({
        "success": False,
        "error": "Failed to update entry"
    }), 500


@api_bp.route('/passwords/<entry_id>', methods=['DELETE'])
@require_auth
def delete_password(entry_id):
    """Delete a password entry"""
    if db.delete_password_entry(entry_id, g.user_id):
        return jsonify({
            "success": True,
            "message": "Entry deleted"
        })
    
    return jsonify({
        "success": False,
        "error": "Password entry not found"
    }), 404


# ==========================================
# Sync Routes
# ==========================================

@api_bp.route('/passwords/sync', methods=['POST'])
@require_auth
def sync_passwords():
    """Sync passwords from client to server"""
    data = request.get_json()
    
    if not data or 'entries' not in data:
        return jsonify({
            "success": False,
            "error": "Entries array required"
        }), 400
    
    entries = []
    for entry_data in data['entries']:
        entry = PasswordEntry(
            id=entry_data.get('id'),
            user_id=g.user_id,
            encrypted_data=entry_data.get('data', ''),
            created_at=entry_data.get('createdAt'),
            updated_at=entry_data.get('updatedAt')
        )
        entries.append(entry)
    
    count = db.upsert_password_entries(g.user_id, entries)
    
    # Log sync
    sync_log = SyncLog(
        user_id=g.user_id,
        sync_type='push',
        entries_synced=count,
        status='success'
    )
    db.create_sync_log(sync_log)
    
    return jsonify({
        "success": True,
        "pushed": count,
        "message": f"Synced {count} entries"
    })


@api_bp.route('/sync/status', methods=['GET'])
@require_auth
def get_sync_status():
    """Get sync status and history"""
    logs = db.get_sync_logs(g.user_id, limit=10)
    stats = db.get_user_stats(g.user_id)
    
    return jsonify({
        "success": True,
        "stats": stats,
        "recent_syncs": [log.to_dict() for log in logs]
    })


# ==========================================
# Password Strength Routes
# ==========================================

@api_bp.route('/password/check', methods=['POST'])
def check_password_strength():
    """Check password strength (no auth required)"""
    data = request.get_json()
    
    if not data or 'password' not in data:
        return jsonify({
            "success": False,
            "error": "Password required"
        }), 400
    
    password = data['password']
    result = PasswordStrengthChecker.validate(password)
    
    return jsonify({
        "success": True,
        **result
    })


# ==========================================
# Error Handlers
# ==========================================

@api_bp.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": "Bad request"
    }), 400


@api_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Resource not found"
    }), 404


@api_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500
