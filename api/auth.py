"""
Password Gatekeeper Pro - Authentication Module
JWT-based authentication for API
"""

from functools import wraps
from flask import request, jsonify, g

from .crypto_utils import CryptoUtils, TokenManager
from .database import db
from .models import User


def require_auth(f):
    """
    Decorator to require authentication for routes
    Sets g.user_id on successful authentication
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({
                "success": False,
                "error": "Authorization header required"
            }), 401
        
        try:
            # Extract token from "Bearer <token>"
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return jsonify({
                    "success": False,
                    "error": "Invalid authorization format"
                }), 401
            
            token = parts[1]
            user_id = TokenManager.verify_token(token)
            
            if not user_id:
                return jsonify({
                    "success": False,
                    "error": "Invalid or expired token"
                }), 401
            
            # Verify user exists and is active
            user = db.get_user_by_id(user_id)
            if not user or not user.is_active:
                return jsonify({
                    "success": False,
                    "error": "User not found or inactive"
                }), 401
            
            g.user_id = user_id
            g.user = user
            
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({
                "success": False,
                "error": str(e)
            }), 401
    
    return decorated


class AuthService:
    """
    Authentication service for user management
    """
    
    @staticmethod
    def register(email: str, password: str) -> dict:
        """
        Register a new user
        
        Args:
            email: User email
            password: Password (should already be hashed by client)
            
        Returns:
            Result dict with success status
        """
        # Validate email
        if not email or '@' not in email:
            return {
                "success": False,
                "error": "Invalid email address"
            }
        
        # Check if user exists
        existing = db.get_user_by_email(email.lower())
        if existing:
            return {
                "success": False,
                "error": "Email already registered"
            }
        
        # Hash the password
        password_hash = CryptoUtils.hash_password(password)
        
        # Create user
        user = User(
            email=email.lower(),
            password_hash=password_hash
        )
        
        try:
            db.create_user(user)
            return {
                "success": True,
                "message": "Registration successful",
                "user_id": user.id
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @staticmethod
    def login(email: str, password: str) -> dict:
        """
        Authenticate user and generate tokens
        
        Args:
            email: User email
            password: Password (hashed by client)
            
        Returns:
            Result dict with tokens if successful
        """
        # Get user
        user = db.get_user_by_email(email.lower())
        if not user:
            return {
                "success": False,
                "error": "Invalid email or password"
            }
        
        # Verify password
        if not CryptoUtils.verify_password(password, user.password_hash):
            return {
                "success": False,
                "error": "Invalid email or password"
            }
        
        # Check if active
        if not user.is_active:
            return {
                "success": False,
                "error": "Account is disabled"
            }
        
        # Generate tokens
        access_token = TokenManager.create_token(user.id, "access")
        refresh_token = TokenManager.create_token(user.id, "refresh")
        
        return {
            "success": True,
            "access_token": access_token["token"],
            "refresh_token": refresh_token["token"],
            "expires_in": access_token["expires_in"],
            "user": user.to_dict()
        }
    
    @staticmethod
    def refresh_token(refresh_token: str) -> dict:
        """
        Refresh access token using refresh token
        
        Args:
            refresh_token: Refresh token string
            
        Returns:
            Result dict with new access token
        """
        user_id = TokenManager.verify_token(refresh_token)
        
        if not user_id:
            return {
                "success": False,
                "error": "Invalid or expired refresh token"
            }
        
        # Verify user still exists and is active
        user = db.get_user_by_id(user_id)
        if not user or not user.is_active:
            return {
                "success": False,
                "error": "User not found or inactive"
            }
        
        # Generate new access token
        access_token = TokenManager.create_token(user_id, "access")
        
        return {
            "success": True,
            "access_token": access_token["token"],
            "expires_in": access_token["expires_in"]
        }
    
    @staticmethod
    def change_password(user_id: str, old_password: str, new_password: str) -> dict:
        """
        Change user password
        
        Args:
            user_id: User ID
            old_password: Current password
            new_password: New password
            
        Returns:
            Result dict
        """
        user = db.get_user_by_id(user_id)
        if not user:
            return {
                "success": False,
                "error": "User not found"
            }
        
        # Verify old password
        if not CryptoUtils.verify_password(old_password, user.password_hash):
            return {
                "success": False,
                "error": "Current password is incorrect"
            }
        
        # Hash new password
        user.password_hash = CryptoUtils.hash_password(new_password)
        
        if db.update_user(user):
            return {
                "success": True,
                "message": "Password changed successfully"
            }
        
        return {
            "success": False,
            "error": "Failed to update password"
        }


# Export service instance
auth_service = AuthService()
