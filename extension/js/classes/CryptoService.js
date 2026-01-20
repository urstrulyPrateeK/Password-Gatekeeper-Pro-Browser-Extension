/**
 * CryptoService Class
 * Handles all encryption/decryption using AES-256-GCM
 * Uses Web Crypto API for secure cryptographic operations
 */

export class CryptoService {
    static ALGORITHM = 'AES-GCM';
    static KEY_LENGTH = 256;
    static IV_LENGTH = 12;
    static SALT_LENGTH = 16;
    static ITERATIONS = 100000;

    #masterKey = null;
    #salt = null;

    constructor() {
        // Initialize with empty state
    }

    /**
     * Check if the vault is unlocked
     * @returns {boolean}
     */
    isUnlocked() {
        return this.#masterKey !== null;
    }

    /**
     * Derive encryption key from master password using PBKDF2
     * @param {string} masterPassword - The master password
     * @param {Uint8Array} salt - Salt for key derivation (optional, generates new if not provided)
     * @returns {Promise<{key: CryptoKey, salt: Uint8Array}>}
     */
    async deriveKey(masterPassword, salt = null) {
        // Generate new salt if not provided
        if (!salt) {
            salt = crypto.getRandomValues(new Uint8Array(CryptoService.SALT_LENGTH));
        }

        // Import master password as raw key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(masterPassword),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // Derive the actual encryption key
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: CryptoService.ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            {
                name: CryptoService.ALGORITHM,
                length: CryptoService.KEY_LENGTH
            },
            true,
            ['encrypt', 'decrypt']
        );

        return { key, salt };
    }

    /**
     * Initialize the service with master password (for vault creation)
     * @param {string} masterPassword - The master password
     * @returns {Promise<string>} - Salt encoded as base64
     */
    async initialize(masterPassword) {
        const { key, salt } = await this.deriveKey(masterPassword);
        this.#masterKey = key;
        this.#salt = salt;
        return this._arrayBufferToBase64(salt);
    }

    /**
     * Unlock the vault with master password and stored salt
     * @param {string} masterPassword - The master password
     * @param {string} saltBase64 - Salt encoded as base64
     * @returns {Promise<boolean>}
     */
    async unlock(masterPassword, saltBase64) {
        try {
            const salt = this._base64ToArrayBuffer(saltBase64);
            const { key } = await this.deriveKey(masterPassword, new Uint8Array(salt));
            this.#masterKey = key;
            this.#salt = new Uint8Array(salt);
            return true;
        } catch (error) {
            console.error('Failed to unlock vault:', error);
            return false;
        }
    }

    /**
     * Lock the vault (clear the master key)
     */
    lock() {
        this.#masterKey = null;
        // Note: salt is kept for re-unlocking
    }

    /**
     * Encrypt data using AES-256-GCM
     * @param {string} plaintext - Data to encrypt
     * @returns {Promise<string>} - Encrypted data as base64 (IV + ciphertext)
     */
    async encrypt(plaintext) {
        if (!this.#masterKey) {
            throw new Error('Vault is locked. Unlock first.');
        }

        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(CryptoService.IV_LENGTH));

        // Encrypt the data
        const encodedData = new TextEncoder().encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: CryptoService.ALGORITHM,
                iv: iv
            },
            this.#masterKey,
            encodedData
        );

        // Combine IV and ciphertext
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(ciphertext), iv.length);

        return this._arrayBufferToBase64(combined);
    }

    /**
     * Decrypt data using AES-256-GCM
     * @param {string} encryptedBase64 - Encrypted data as base64
     * @returns {Promise<string>} - Decrypted plaintext
     */
    async decrypt(encryptedBase64) {
        if (!this.#masterKey) {
            throw new Error('Vault is locked. Unlock first.');
        }

        try {
            const combined = new Uint8Array(this._base64ToArrayBuffer(encryptedBase64));

            // Extract IV and ciphertext
            const iv = combined.slice(0, CryptoService.IV_LENGTH);
            const ciphertext = combined.slice(CryptoService.IV_LENGTH);

            // Decrypt
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: CryptoService.ALGORITHM,
                    iv: iv
                },
                this.#masterKey,
                ciphertext
            );

            return new TextDecoder().decode(decrypted);
        } catch (error) {
            console.error('Decryption failed:', error);
            throw new Error('Failed to decrypt data. Invalid password or corrupted data.');
        }
    }

    /**
     * Create a verification token to validate master password
     * @returns {Promise<string>}
     */
    async createVerificationToken() {
        const token = 'PASSWORD_GATEKEEPER_VERIFICATION_TOKEN_v1';
        return await this.encrypt(token);
    }

    /**
     * Verify the master password using stored token
     * @param {string} encryptedToken - Encrypted verification token
     * @returns {Promise<boolean>}
     */
    async verifyMasterPassword(encryptedToken) {
        try {
            const decrypted = await this.decrypt(encryptedToken);
            return decrypted === 'PASSWORD_GATEKEEPER_VERIFICATION_TOKEN_v1';
        } catch {
            return false;
        }
    }

    /**
     * Generate a hash of the master password for comparison
     * @param {string} password - Password to hash
     * @returns {Promise<string>}
     */
    async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return this._arrayBufferToBase64(hashBuffer);
    }

    /**
     * Generate a secure random password
     * @param {number} length - Password length
     * @returns {string}
     */
    generateRandomPassword(length = 16) {
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        const randomValues = crypto.getRandomValues(new Uint32Array(length));
        let password = '';

        for (let i = 0; i < length; i++) {
            password += charset[randomValues[i] % charset.length];
        }

        return password;
    }

    /**
     * Get the current salt as base64
     * @returns {string|null}
     */
    getSalt() {
        return this.#salt ? this._arrayBufferToBase64(this.#salt) : null;
    }

    /**
     * Export the key for backup (encrypted with another password)
     * @param {string} backupPassword - Password to protect the backup
     * @returns {Promise<string>}
     */
    async exportKey(backupPassword) {
        if (!this.#masterKey) {
            throw new Error('Vault is locked');
        }

        // Export the raw key
        const rawKey = await crypto.subtle.exportKey('raw', this.#masterKey);

        // Encrypt with backup password
        const { key: backupKey, salt: backupSalt } = await this.deriveKey(backupPassword);
        const iv = crypto.getRandomValues(new Uint8Array(CryptoService.IV_LENGTH));

        const encryptedKey = await crypto.subtle.encrypt(
            { name: CryptoService.ALGORITHM, iv },
            backupKey,
            rawKey
        );

        // Combine all parts
        const combined = new Uint8Array(
            backupSalt.length + iv.length + encryptedKey.byteLength
        );
        combined.set(backupSalt);
        combined.set(iv, backupSalt.length);
        combined.set(new Uint8Array(encryptedKey), backupSalt.length + iv.length);

        return this._arrayBufferToBase64(combined);
    }

    // Utility methods for base64 conversion
    _arrayBufferToBase64(buffer) {
        const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    _base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
}

// Singleton instance
export const cryptoService = new CryptoService();
