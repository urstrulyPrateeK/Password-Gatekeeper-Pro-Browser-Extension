/**
 * StorageService Class
 * Handles file handling and local storage operations
 * Uses Chrome Storage API with encryption layer
 */

import { cryptoService } from './CryptoService.js';
import { PasswordEntry } from './PasswordEntry.js';

export class StorageService {
    static STORAGE_KEYS = {
        VAULT_DATA: 'vault_data',
        VAULT_SALT: 'vault_salt',
        VAULT_TOKEN: 'vault_token',
        SETTINGS: 'settings',
        LAST_SYNC: 'last_sync',
        TRIE_DATA: 'trie_data'
    };

    constructor() {
        this.cache = new Map();
        this.isDirty = false;
    }

    /**
     * Check if vault exists
     * @returns {Promise<boolean>}
     */
    async vaultExists() {
        const salt = await this.get(StorageService.STORAGE_KEYS.VAULT_SALT);
        return salt !== null;
    }

    /**
     * Create a new vault
     * @param {string} masterPassword 
     * @returns {Promise<void>}
     */
    async createVault(masterPassword) {
        const salt = await cryptoService.initialize(masterPassword);
        const token = await cryptoService.createVerificationToken();

        await this.set(StorageService.STORAGE_KEYS.VAULT_SALT, salt);
        await this.set(StorageService.STORAGE_KEYS.VAULT_TOKEN, token);
        await this.set(StorageService.STORAGE_KEYS.VAULT_DATA, []);
    }

    /**
     * Unlock existing vault
     * @param {string} masterPassword 
     * @returns {Promise<boolean>}
     */
    async unlockVault(masterPassword) {
        const salt = await this.get(StorageService.STORAGE_KEYS.VAULT_SALT);
        if (!salt) {
            throw new Error('Vault does not exist');
        }

        const unlocked = await cryptoService.unlock(masterPassword, salt);
        if (!unlocked) {
            return false;
        }

        // Verify with token
        const token = await this.get(StorageService.STORAGE_KEYS.VAULT_TOKEN);
        if (token) {
            const valid = await cryptoService.verifyMasterPassword(token);
            if (!valid) {
                cryptoService.lock();
                return false;
            }
        }

        return true;
    }

    /**
     * Lock the vault
     */
    lockVault() {
        cryptoService.lock();
        this.cache.clear();
    }

    /**
     * Get all password entries
     * @returns {Promise<PasswordEntry[]>}
     */
    async getPasswords() {
        if (!cryptoService.isUnlocked()) {
            throw new Error('Vault is locked');
        }

        const encrypted = await this.get(StorageService.STORAGE_KEYS.VAULT_DATA);
        if (!encrypted || !Array.isArray(encrypted)) {
            return [];
        }

        const entries = [];
        for (const encryptedEntry of encrypted) {
            try {
                const decrypted = await cryptoService.decrypt(encryptedEntry);
                const data = JSON.parse(decrypted);
                entries.push(PasswordEntry.fromJSON(data));
            } catch (error) {
                console.error('Failed to decrypt entry:', error);
            }
        }

        return entries;
    }

    /**
     * Save password entries
     * @param {PasswordEntry[]} entries 
     * @returns {Promise<void>}
     */
    async savePasswords(entries) {
        if (!cryptoService.isUnlocked()) {
            throw new Error('Vault is locked');
        }

        const encrypted = [];
        for (const entry of entries) {
            const json = JSON.stringify(entry.toJSON());
            const encryptedEntry = await cryptoService.encrypt(json);
            encrypted.push(encryptedEntry);
        }

        await this.set(StorageService.STORAGE_KEYS.VAULT_DATA, encrypted);
        this.isDirty = true;
    }

    /**
     * Add a new password entry
     * @param {PasswordEntry} entry 
     * @returns {Promise<void>}
     */
    async addPassword(entry) {
        const entries = await this.getPasswords();
        entries.push(entry);
        await this.savePasswords(entries);
    }

    /**
     * Update an existing password entry
     * @param {string} id 
     * @param {Object} updates 
     * @returns {Promise<boolean>}
     */
    async updatePassword(id, updates) {
        const entries = await this.getPasswords();
        const index = entries.findIndex(e => e.id === id);

        if (index === -1) {
            return false;
        }

        const entry = entries[index];
        if (updates.website) entry.setWebsite(updates.website);
        if (updates.username) entry.setUsername(updates.username);
        if (updates.encryptedPassword) entry.encryptedPassword = updates.encryptedPassword;
        if (updates.notes !== undefined) entry.setNotes(updates.notes);
        if (updates.tags) entry.setTags(updates.tags);
        if (updates.strength !== undefined) entry.strength = updates.strength;

        await this.savePasswords(entries);
        return true;
    }

    /**
     * Delete a password entry
     * @param {string} id 
     * @returns {Promise<boolean>}
     */
    async deletePassword(id) {
        const entries = await this.getPasswords();
        const filtered = entries.filter(e => e.id !== id);

        if (filtered.length === entries.length) {
            return false;
        }

        await this.savePasswords(filtered);
        return true;
    }

    /**
     * Get a specific password entry
     * @param {string} id 
     * @returns {Promise<PasswordEntry|null>}
     */
    async getPassword(id) {
        const entries = await this.getPasswords();
        return entries.find(e => e.id === id) || null;
    }

    /**
     * Search password entries
     * @param {string} query 
     * @returns {Promise<PasswordEntry[]>}
     */
    async searchPasswords(query) {
        const entries = await this.getPasswords();
        return entries.filter(e => e.matches(query));
    }

    // Settings management

    /**
     * Get settings
     * @returns {Promise<Object>}
     */
    async getSettings() {
        const settings = await this.get(StorageService.STORAGE_KEYS.SETTINGS);
        return settings || this.getDefaultSettings();
    }

    /**
     * Save settings
     * @param {Object} settings 
     * @returns {Promise<void>}
     */
    async saveSettings(settings) {
        await this.set(StorageService.STORAGE_KEYS.SETTINGS, settings);
    }

    /**
     * Get default settings
     * @returns {Object}
     */
    getDefaultSettings() {
        return {
            autoLockTime: 5,
            clearClipboard: true,
            clipboardTimeout: 30,
            apiUrl: '',
            syncEmail: '',
            darkMode: true
        };
    }

    // Export/Import functionality

    /**
     * Export vault to encrypted JSON file
     * @returns {Promise<string>}
     */
    async exportVault() {
        if (!cryptoService.isUnlocked()) {
            throw new Error('Vault is locked');
        }

        const entries = await this.getPasswords();
        const settings = await this.getSettings();

        const exportData = {
            version: '1.0',
            exportDate: new Date().toISOString(),
            entries: entries.map(e => e.toJSON()),
            settings
        };

        // Encrypt the export
        const encrypted = await cryptoService.encrypt(JSON.stringify(exportData));

        return JSON.stringify({
            type: 'PASSWORD_GATEKEEPER_EXPORT',
            version: '1.0',
            data: encrypted
        });
    }

    /**
     * Import vault from encrypted JSON file
     * @param {string} jsonString 
     * @param {boolean} merge - Merge with existing or replace
     * @returns {Promise<{success: boolean, imported: number, errors: string[]}>}
     */
    async importVault(jsonString, merge = true) {
        if (!cryptoService.isUnlocked()) {
            throw new Error('Vault is locked');
        }

        try {
            const importWrapper = JSON.parse(jsonString);

            if (importWrapper.type !== 'PASSWORD_GATEKEEPER_EXPORT') {
                throw new Error('Invalid export file format');
            }

            const decrypted = await cryptoService.decrypt(importWrapper.data);
            const importData = JSON.parse(decrypted);

            let entries = merge ? await this.getPasswords() : [];
            const importedEntries = PasswordEntry.fromJSONArray(importData.entries);

            if (merge) {
                // Avoid duplicates by id
                const existingIds = new Set(entries.map(e => e.id));
                for (const entry of importedEntries) {
                    if (!existingIds.has(entry.id)) {
                        entries.push(entry);
                    }
                }
            } else {
                entries = importedEntries;
            }

            await this.savePasswords(entries);

            return {
                success: true,
                imported: importedEntries.length,
                errors: []
            };
        } catch (error) {
            return {
                success: false,
                imported: 0,
                errors: [error.message]
            };
        }
    }

    /**
     * Reset the entire vault
     * @returns {Promise<void>}
     */
    async resetVault() {
        await chrome.storage.local.clear();
        cryptoService.lock();
        this.cache.clear();
    }

    // Low-level storage operations

    /**
     * Get value from storage
     * @param {string} key 
     * @returns {Promise<any>}
     */
    async get(key) {
        // Check cache first
        if (this.cache.has(key)) {
            return this.cache.get(key);
        }

        try {
            const result = await chrome.storage.local.get(key);
            const value = result[key] || null;
            this.cache.set(key, value);
            return value;
        } catch (error) {
            console.error('Storage get error:', error);
            return null;
        }
    }

    /**
     * Set value in storage
     * @param {string} key 
     * @param {any} value 
     * @returns {Promise<void>}
     */
    async set(key, value) {
        try {
            await chrome.storage.local.set({ [key]: value });
            this.cache.set(key, value);
        } catch (error) {
            console.error('Storage set error:', error);
            throw error;
        }
    }

    /**
     * Remove value from storage
     * @param {string} key 
     * @returns {Promise<void>}
     */
    async remove(key) {
        try {
            await chrome.storage.local.remove(key);
            this.cache.delete(key);
        } catch (error) {
            console.error('Storage remove error:', error);
        }
    }

    /**
     * Get storage usage stats
     * @returns {Promise<Object>}
     */
    async getStorageStats() {
        const entries = await this.getPasswords();
        const bytesUsed = await chrome.storage.local.getBytesInUse();

        return {
            totalEntries: entries.length,
            bytesUsed,
            bytesAvailable: chrome.storage.local.QUOTA_BYTES - bytesUsed,
            percentUsed: (bytesUsed / chrome.storage.local.QUOTA_BYTES * 100).toFixed(2)
        };
    }
}

// Singleton instance
export const storageService = new StorageService();
