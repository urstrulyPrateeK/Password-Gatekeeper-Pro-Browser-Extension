"""
Password Gatekeeper Pro - Crypto Utilities
AES-256-GCM encryption for server-side operations
"""

import os
import base64
import hashlib
import secrets
from typing import Tuple, Optional

# Try to import cryptography library
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not installed. Using fallback.")


class CryptoUtils:
    """
    Cryptographic utilities for server-side encryption
    Uses AES-256-GCM with PBKDF2 key derivation
    """
    
    SALT_LENGTH = 16
    IV_LENGTH = 12
    KEY_LENGTH = 32  # 256 bits
    ITERATIONS = 100000
    
    @classmethod
    def generate_salt(cls) -> bytes:
        """Generate a cryptographically secure salt"""
        return secrets.token_bytes(cls.SALT_LENGTH)
    
    @classmethod
    def generate_iv(cls) -> bytes:
        """Generate a cryptographically secure IV for AES-GCM"""
        return secrets.token_bytes(cls.IV_LENGTH)
    
    @classmethod
    def derive_key(cls, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: User password
            salt: Salt bytes
            
        Returns:
            Derived key bytes
        """
        if CRYPTO_AVAILABLE:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=cls.KEY_LENGTH,
                salt=salt,
                iterations=cls.ITERATIONS,
                backend=default_backend()
            )
            return kdf.derive(password.encode())
        else:
            # Fallback using hashlib
            return hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                salt,
                cls.ITERATIONS,
                dklen=cls.KEY_LENGTH
            )
    
    @classmethod
    def encrypt(cls, plaintext: str, password: str) -> str:
        """
        Encrypt plaintext using AES-256-GCM
        
        Args:
            plaintext: Data to encrypt
            password: Encryption password
            
        Returns:
            Base64 encoded string (salt + iv + ciphertext)
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library required for encryption")
        
        salt = cls.generate_salt()
        iv = cls.generate_iv()
        key = cls.derive_key(password, salt)
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)
        
        # Combine salt + iv + ciphertext
        combined = salt + iv + ciphertext
        return base64.b64encode(combined).decode()
    
    @classmethod
    def decrypt(cls, encrypted: str, password: str) -> str:
        """
        Decrypt ciphertext using AES-256-GCM
        
        Args:
            encrypted: Base64 encoded encrypted data
            password: Decryption password
            
        Returns:
            Decrypted plaintext
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library required for decryption")
        
        combined = base64.b64decode(encrypted)
        
        salt = combined[:cls.SALT_LENGTH]
        iv = combined[cls.SALT_LENGTH:cls.SALT_LENGTH + cls.IV_LENGTH]
        ciphertext = combined[cls.SALT_LENGTH + cls.IV_LENGTH:]
        
        key = cls.derive_key(password, salt)
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        
        return plaintext.decode()
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Create secure hash of password for storage
        Uses PBKDF2-SHA256 with random salt
        
        Args:
            password: Password to hash
            
        Returns:
            Hash string in format: salt$hash (both base64)
        """
        salt = cls.generate_salt()
        key = cls.derive_key(password, salt)
        
        salt_b64 = base64.b64encode(salt).decode()
        hash_b64 = base64.b64encode(key).decode()
        
        return f"{salt_b64}${hash_b64}"
    
    @classmethod
    def verify_password(cls, password: str, stored_hash: str) -> bool:
        """
        Verify password against stored hash
        
        Args:
            password: Password to verify
            stored_hash: Stored hash string (salt$hash format)
            
        Returns:
            True if password matches
        """
        try:
            salt_b64, hash_b64 = stored_hash.split('$')
            salt = base64.b64decode(salt_b64)
            stored_key = base64.b64decode(hash_b64)
            
            computed_key = cls.derive_key(password, salt)
            
            return secrets.compare_digest(computed_key, stored_key)
        except Exception:
            return False
    
    @classmethod
    def generate_token(cls, length: int = 32) -> str:
        """Generate a secure random token"""
        return secrets.token_urlsafe(length)
    
    @classmethod
    def hash_sha256(cls, data: str) -> str:
        """Simple SHA-256 hash"""
        return hashlib.sha256(data.encode()).hexdigest()


class TokenManager:
    """
    JWT-like token management (simplified)
    For production, use proper JWT library
    """
    
    TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
    REFRESH_EXPIRY_SECONDS = 86400 * 7  # 7 days
    
    _secret_key: Optional[str] = None
    
    @classmethod
    def get_secret_key(cls) -> str:
        """Get or generate secret key"""
        if cls._secret_key is None:
            # In production, this should be from environment variable
            cls._secret_key = os.environ.get(
                'JWT_SECRET_KEY', 
                CryptoUtils.generate_token(48)
            )
        return cls._secret_key
    
    @classmethod
    def create_token(cls, user_id: str, token_type: str = "access") -> dict:
        """
        Create an access or refresh token
        
        Args:
            user_id: User ID to encode in token
            token_type: 'access' or 'refresh'
            
        Returns:
            Token dict with token string and expiry
        """
        import time
        
        expiry = cls.TOKEN_EXPIRY_SECONDS if token_type == "access" else cls.REFRESH_EXPIRY_SECONDS
        expires_at = int(time.time()) + expiry
        
        # Create token payload
        payload = f"{user_id}:{token_type}:{expires_at}"
        
        # Sign with HMAC
        signature = hashlib.sha256(
            (payload + cls.get_secret_key()).encode()
        ).hexdigest()[:32]
        
        token = base64.urlsafe_b64encode(
            f"{payload}:{signature}".encode()
        ).decode()
        
        return {
            "token": token,
            "expires_in": expiry,
            "expires_at": expires_at
        }
    
    @classmethod
    def verify_token(cls, token: str) -> Optional[str]:
        """
        Verify a token and return user_id if valid
        
        Args:
            token: Token string to verify
            
        Returns:
            User ID if valid, None otherwise
        """
        import time
        
        try:
            decoded = base64.urlsafe_b64decode(token).decode()
            parts = decoded.rsplit(':', 1)
            
            if len(parts) != 2:
                return None
            
            payload, signature = parts
            user_id, token_type, expires_at = payload.split(':')
            
            # Check expiry
            if int(expires_at) < int(time.time()):
                return None
            
            # Verify signature
            expected_sig = hashlib.sha256(
                (payload + cls.get_secret_key()).encode()
            ).hexdigest()[:32]
            
            if not secrets.compare_digest(signature, expected_sig):
                return None
            
            return user_id
            
        except Exception:
            return None
