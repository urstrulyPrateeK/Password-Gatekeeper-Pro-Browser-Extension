"""
Password Gatekeeper Pro - Python Models
OOP Implementation for database models
"""

from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional
import uuid


@dataclass
class User:
    """User model representing a registered account"""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    email: str = ""
    password_hash: str = ""
    master_key_hash: str = ""  # Hash of master password for verification
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    is_active: bool = True
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "email": self.email,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_active": self.is_active
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'User':
        """Create User instance from dictionary"""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            email=data.get("email", ""),
            password_hash=data.get("password_hash", ""),
            master_key_hash=data.get("master_key_hash", ""),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            updated_at=data.get("updated_at", datetime.utcnow().isoformat()),
            is_active=data.get("is_active", True)
        )
    
    def update_timestamp(self):
        """Update the updated_at timestamp"""
        self.updated_at = datetime.utcnow().isoformat()


@dataclass
class PasswordEntry:
    """Password entry model - stores encrypted password data"""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    encrypted_data: str = ""  # Entire entry encrypted by client
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "data": self.encrypted_data,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'PasswordEntry':
        """Create PasswordEntry instance from dictionary"""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            user_id=data.get("user_id", ""),
            encrypted_data=data.get("data", data.get("encrypted_data", "")),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            updated_at=data.get("updated_at", datetime.utcnow().isoformat())
        )
    
    def update_timestamp(self):
        """Update the updated_at timestamp"""
        self.updated_at = datetime.utcnow().isoformat()


@dataclass  
class SyncLog:
    """Sync log for tracking synchronization history"""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    sync_type: str = ""  # 'push', 'pull', 'merge'
    entries_synced: int = 0
    status: str = "success"  # 'success', 'partial', 'failed'
    message: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "sync_type": self.sync_type,
            "entries_synced": self.entries_synced,
            "status": self.status,
            "message": self.message,
            "created_at": self.created_at
        }


class PasswordStrengthChecker:
    """
    Password strength validation class
    Ported from original Python implementation with enhancements
    """
    
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
        'master', 'dragon', 'letmein', 'login', 'admin', 'welcome',
        'password1', 'password123', 'iloveyou', 'sunshine', 'princess'
    }
    
    @classmethod
    def check_strength(cls, password: str) -> str:
        """
        Check password strength - matches original Python implementation
        
        Args:
            password: Password to check
            
        Returns:
            Strength label: "Strong Password", "Medium Password", "Weak Password", "Invalid Password"
        """
        if not password or len(password) < 8:
            return "Weak Password"
        
        if ' ' in password:
            return "Invalid Password"
        
        has_upper = False
        has_lower = False
        has_digit = False
        has_special = False
        
        for ch in password:
            if 'A' <= ch <= 'Z':
                has_upper = True
            elif 'a' <= ch <= 'z':
                has_lower = True
            elif '0' <= ch <= '9':
                has_digit = True
            else:
                has_special = True
        
        if has_upper and has_lower and has_digit and has_special:
            return "Strong Password"
        
        if (has_upper or has_lower) and has_digit:
            return "Medium Password"
        
        return "Weak Password"
    
    @classmethod
    def get_score(cls, password: str) -> int:
        """
        Get numeric score for password strength (0-100)
        """
        if not password:
            return 0
        
        score = 0
        
        # Length scoring
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 15
        if len(password) >= 16:
            score += 10
        
        # Character variety
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if has_upper:
            score += 15
        if has_lower:
            score += 10
        if has_digit:
            score += 15
        if has_special:
            score += 15
        
        # Common password penalty
        if password.lower() in cls.COMMON_PASSWORDS:
            score = max(0, score - 50)
        
        return min(100, score)
    
    @classmethod
    def validate(cls, password: str) -> dict:
        """
        Complete password validation with details
        """
        strength = cls.check_strength(password)
        score = cls.get_score(password)
        
        return {
            "password_length": len(password) if password else 0,
            "strength": strength,
            "score": score,
            "has_uppercase": any(c.isupper() for c in password) if password else False,
            "has_lowercase": any(c.islower() for c in password) if password else False,
            "has_digit": any(c.isdigit() for c in password) if password else False,
            "has_special": any(not c.isalnum() for c in password) if password else False,
            "is_common": password.lower() in cls.COMMON_PASSWORDS if password else False
        }
