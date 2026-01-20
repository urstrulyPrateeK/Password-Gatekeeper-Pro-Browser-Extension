"""
Password Gatekeeper Pro - Database Layer
SQLite database with encrypted field storage
"""

import sqlite3
import json
import os
from typing import List, Optional
from contextlib import contextmanager
from datetime import datetime

from .models import User, PasswordEntry, SyncLog


class Database:
    """
    SQLite database handler with connection pooling
    Implements file handling for persistent storage
    """
    
    def __init__(self, db_path: str = None):
        """
        Initialize database connection
        
        Args:
            db_path: Path to SQLite database file
        """
        if db_path is None:
            # Default to same directory as app
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, 'password_vault.db')
        
        self.db_path = db_path
        self._init_database()
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections
        Ensures proper connection handling
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_database(self):
        """Create database tables if they don't exist"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    master_key_hash TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            # Password entries table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_entries (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Sync logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sync_logs (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    sync_type TEXT NOT NULL,
                    entries_synced INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    message TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Create indexes
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_entries_user 
                ON password_entries(user_id)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sync_user 
                ON sync_logs(user_id)
            ''')
    
    # ==========================================
    # User Operations
    # ==========================================
    
    def create_user(self, user: User) -> User:
        """
        Create a new user
        
        Args:
            user: User object to create
            
        Returns:
            Created user with ID
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (id, email, password_hash, master_key_hash, 
                                   created_at, updated_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                user.id, user.email, user.password_hash, user.master_key_hash,
                user.created_at, user.updated_at, int(user.is_active)
            ))
        return user
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email address"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            
            if row:
                return User(
                    id=row['id'],
                    email=row['email'],
                    password_hash=row['password_hash'],
                    master_key_hash=row['master_key_hash'] or '',
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    is_active=bool(row['is_active'])
                )
        return None
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            
            if row:
                return User(
                    id=row['id'],
                    email=row['email'],
                    password_hash=row['password_hash'],
                    master_key_hash=row['master_key_hash'] or '',
                    created_at=row['created_at'],
                    updated_at=row['updated_at'],
                    is_active=bool(row['is_active'])
                )
        return None
    
    def update_user(self, user: User) -> bool:
        """Update user data"""
        user.update_timestamp()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET email = ?, password_hash = ?, master_key_hash = ?,
                    updated_at = ?, is_active = ?
                WHERE id = ?
            ''', (
                user.email, user.password_hash, user.master_key_hash,
                user.updated_at, int(user.is_active), user.id
            ))
            return cursor.rowcount > 0
    
    # ==========================================
    # Password Entry Operations
    # ==========================================
    
    def create_password_entry(self, entry: PasswordEntry) -> PasswordEntry:
        """Create a new password entry"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO password_entries (id, user_id, encrypted_data, 
                                              created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                entry.id, entry.user_id, entry.encrypted_data,
                entry.created_at, entry.updated_at
            ))
        return entry
    
    def get_password_entries(self, user_id: str) -> List[PasswordEntry]:
        """Get all password entries for a user"""
        entries = []
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM password_entries WHERE user_id = ?
                ORDER BY updated_at DESC
            ''', (user_id,))
            
            for row in cursor.fetchall():
                entries.append(PasswordEntry(
                    id=row['id'],
                    user_id=row['user_id'],
                    encrypted_data=row['encrypted_data'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at']
                ))
        return entries
    
    def get_password_entry(self, entry_id: str, user_id: str) -> Optional[PasswordEntry]:
        """Get a specific password entry"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM password_entries 
                WHERE id = ? AND user_id = ?
            ''', (entry_id, user_id))
            row = cursor.fetchone()
            
            if row:
                return PasswordEntry(
                    id=row['id'],
                    user_id=row['user_id'],
                    encrypted_data=row['encrypted_data'],
                    created_at=row['created_at'],
                    updated_at=row['updated_at']
                )
        return None
    
    def update_password_entry(self, entry: PasswordEntry) -> bool:
        """Update a password entry"""
        entry.update_timestamp()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE password_entries 
                SET encrypted_data = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
            ''', (
                entry.encrypted_data, entry.updated_at,
                entry.id, entry.user_id
            ))
            return cursor.rowcount > 0
    
    def delete_password_entry(self, entry_id: str, user_id: str) -> bool:
        """Delete a password entry"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM password_entries 
                WHERE id = ? AND user_id = ?
            ''', (entry_id, user_id))
            return cursor.rowcount > 0
    
    def upsert_password_entries(self, user_id: str, entries: List[PasswordEntry]) -> int:
        """
        Upsert multiple password entries (for sync)
        
        Args:
            user_id: User ID
            entries: List of entries to upsert
            
        Returns:
            Number of entries processed
        """
        count = 0
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            for entry in entries:
                entry.user_id = user_id
                
                # Check if exists
                cursor.execute(
                    'SELECT id FROM password_entries WHERE id = ? AND user_id = ?',
                    (entry.id, user_id)
                )
                
                if cursor.fetchone():
                    # Update
                    cursor.execute('''
                        UPDATE password_entries 
                        SET encrypted_data = ?, updated_at = ?
                        WHERE id = ? AND user_id = ?
                    ''', (entry.encrypted_data, entry.updated_at, entry.id, user_id))
                else:
                    # Insert
                    cursor.execute('''
                        INSERT INTO password_entries (id, user_id, encrypted_data, 
                                                      created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        entry.id, user_id, entry.encrypted_data,
                        entry.created_at, entry.updated_at
                    ))
                count += 1
        
        return count
    
    # ==========================================
    # Sync Log Operations
    # ==========================================
    
    def create_sync_log(self, log: SyncLog) -> SyncLog:
        """Create a sync log entry"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sync_logs (id, user_id, sync_type, entries_synced,
                                       status, message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                log.id, log.user_id, log.sync_type, log.entries_synced,
                log.status, log.message, log.created_at
            ))
        return log
    
    def get_sync_logs(self, user_id: str, limit: int = 10) -> List[SyncLog]:
        """Get recent sync logs for a user"""
        logs = []
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM sync_logs 
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            ''', (user_id, limit))
            
            for row in cursor.fetchall():
                logs.append(SyncLog(
                    id=row['id'],
                    user_id=row['user_id'],
                    sync_type=row['sync_type'],
                    entries_synced=row['entries_synced'],
                    status=row['status'],
                    message=row['message'],
                    created_at=row['created_at']
                ))
        return logs
    
    # ==========================================
    # Statistics
    # ==========================================
    
    def get_user_stats(self, user_id: str) -> dict:
        """Get statistics for a user"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Count entries
            cursor.execute(
                'SELECT COUNT(*) as count FROM password_entries WHERE user_id = ?',
                (user_id,)
            )
            entry_count = cursor.fetchone()['count']
            
            # Count syncs
            cursor.execute(
                'SELECT COUNT(*) as count FROM sync_logs WHERE user_id = ?',
                (user_id,)
            )
            sync_count = cursor.fetchone()['count']
            
            # Last sync
            cursor.execute('''
                SELECT created_at FROM sync_logs 
                WHERE user_id = ? 
                ORDER BY created_at DESC LIMIT 1
            ''', (user_id,))
            row = cursor.fetchone()
            last_sync = row['created_at'] if row else None
            
            return {
                "password_count": entry_count,
                "sync_count": sync_count,
                "last_sync": last_sync
            }


# Singleton database instance
db = Database()
