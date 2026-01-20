/**
 * PasswordManager Class
 * Main controller that coordinates all services
 * Implements Facade pattern for simplified API
 */

import { PasswordEntry } from './PasswordEntry.js';
import { PasswordValidator } from './PasswordValidator.js';
import { PasswordGenerator } from './PasswordGenerator.js';
import { cryptoService } from './CryptoService.js';
import { storageService } from './StorageService.js';
import { syncService } from './SyncService.js';
import { Trie } from '../dsa/Trie.js';
import { HashMap } from '../dsa/HashMap.js';
import { SortingAlgorithms } from '../dsa/SortingAlgorithms.js';
import { LevenshteinDistance } from '../dsa/LevenshteinDistance.js';
import { BinarySearch } from '../dsa/BinarySearch.js';

export class PasswordManager {
    constructor() {
        // DSA data structures for efficient operations
        this.websiteTrie = new Trie();
        this.passwordMap = new HashMap();
        this.entriesCache = [];
        this.isInitialized = false;
    }

    // ==========================================
    // Initialization & Vault Management
    // ==========================================

    /**
     * Initialize the password manager
     * @returns {Promise<{exists: boolean, unlocked: boolean}>}
     */
    async initialize() {
        const exists = await storageService.vaultExists();
        const unlocked = cryptoService.isUnlocked();

        if (unlocked) {
            await this._loadDataStructures();
        }

        this.isInitialized = true;

        return { exists, unlocked };
    }

    /**
     * Create a new vault
     * @param {string} masterPassword 
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async createVault(masterPassword) {
        // Validate master password strength
        const validation = PasswordValidator.validate(masterPassword);
        if (validation.score < 40) {
            return {
                success: false,
                message: 'Master password is too weak. Please use a stronger password.',
                suggestions: validation.suggestions
            };
        }

        try {
            await storageService.createVault(masterPassword);
            await this._loadDataStructures();

            return { success: true, message: 'Vault created successfully' };
        } catch (error) {
            return { success: false, message: error.message };
        }
    }

    /**
     * Unlock the vault
     * @param {string} masterPassword 
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async unlockVault(masterPassword) {
        try {
            const unlocked = await storageService.unlockVault(masterPassword);

            if (unlocked) {
                await this._loadDataStructures();
                return { success: true, message: 'Vault unlocked' };
            } else {
                return { success: false, message: 'Incorrect master password' };
            }
        } catch (error) {
            return { success: false, message: error.message };
        }
    }

    /**
     * Lock the vault
     */
    lockVault() {
        storageService.lockVault();
        this.websiteTrie.clear();
        this.passwordMap.clear();
        this.entriesCache = [];
    }

    /**
     * Check if vault is unlocked
     * @returns {boolean}
     */
    isUnlocked() {
        return cryptoService.isUnlocked();
    }

    // ==========================================
    // Password CRUD Operations
    // ==========================================

    /**
     * Add a new password entry
     * @param {Object} data 
     * @returns {Promise<{success: boolean, entry: PasswordEntry, message: string}>}
     */
    async addPassword(data) {
        if (!this.isUnlocked()) {
            return { success: false, message: 'Vault is locked' };
        }

        try {
            // Validate strength
            const validation = PasswordValidator.validate(data.password);

            // Encrypt the password
            const encryptedPassword = await cryptoService.encrypt(data.password);

            // Create entry
            const entry = new PasswordEntry({
                website: data.website,
                username: data.username,
                encryptedPassword: encryptedPassword,
                notes: data.notes || '',
                tags: data.tags || [],
                strength: validation.score
            });

            // Validate entry
            const entryValidation = entry.validate();
            if (!entryValidation.isValid) {
                return { success: false, message: entryValidation.errors.join(', ') };
            }

            // Save to storage
            await storageService.addPassword(entry);

            // Update DSA structures
            this._addToDataStructures(entry);

            return { success: true, entry, message: 'Password saved successfully' };
        } catch (error) {
            return { success: false, message: error.message };
        }
    }

    /**
     * Update an existing password entry
     * @param {string} id 
     * @param {Object} updates 
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async updatePassword(id, updates) {
        if (!this.isUnlocked()) {
            return { success: false, message: 'Vault is locked' };
        }

        try {
            // If password is being updated, encrypt it
            if (updates.password) {
                const validation = PasswordValidator.validate(updates.password);
                updates.encryptedPassword = await cryptoService.encrypt(updates.password);
                updates.strength = validation.score;
                delete updates.password;
            }

            const success = await storageService.updatePassword(id, updates);

            if (success) {
                await this._loadDataStructures(); // Refresh
                return { success: true, message: 'Password updated successfully' };
            } else {
                return { success: false, message: 'Password not found' };
            }
        } catch (error) {
            return { success: false, message: error.message };
        }
    }

    /**
     * Delete a password entry
     * @param {string} id 
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async deletePassword(id) {
        if (!this.isUnlocked()) {
            return { success: false, message: 'Vault is locked' };
        }

        try {
            const entry = await storageService.getPassword(id);
            if (!entry) {
                return { success: false, message: 'Password not found' };
            }

            const success = await storageService.deletePassword(id);

            if (success) {
                // Remove from DSA structures
                this.websiteTrie.delete(entry.website);
                this.passwordMap.remove(entry.website);
                this.entriesCache = this.entriesCache.filter(e => e.id !== id);

                return { success: true, message: 'Password deleted successfully' };
            } else {
                return { success: false, message: 'Failed to delete password' };
            }
        } catch (error) {
            return { success: false, message: error.message };
        }
    }

    /**
     * Get all password entries
     * @param {string} sortBy - Sorting criteria
     * @returns {Promise<PasswordEntry[]>}
     */
    async getAllPasswords(sortBy = 'website') {
        if (!this.isUnlocked()) {
            return [];
        }

        const entries = await storageService.getPasswords();
        return SortingAlgorithms.sortEntries(entries, sortBy);
    }

    /**
     * Get decrypted password for an entry
     * @param {string} id 
     * @returns {Promise<string|null>}
     */
    async getDecryptedPassword(id) {
        if (!this.isUnlocked()) {
            return null;
        }

        const entry = await storageService.getPassword(id);
        if (!entry) return null;

        try {
            return await cryptoService.decrypt(entry.encryptedPassword);
        } catch {
            return null;
        }
    }

    // ==========================================
    // Search & Autocomplete (Using DSA)
    // ==========================================

    /**
     * Search passwords with query
     * @param {string} query 
     * @returns {Promise<PasswordEntry[]>}
     */
    async searchPasswords(query) {
        if (!this.isUnlocked() || !query) {
            return this.entriesCache;
        }

        // Use Trie for prefix search
        const trieResults = this.websiteTrie.autocomplete(query.toLowerCase());
        const matchedIds = new Set(trieResults.map(r => r.data?.id).filter(Boolean));

        // Also do full-text search on cached entries
        const textMatches = this.entriesCache.filter(e =>
            e.matches(query) && !matchedIds.has(e.id)
        );

        // Combine results
        const trieEntries = trieResults
            .map(r => this.entriesCache.find(e => e.id === r.data?.id))
            .filter(Boolean);

        return [...trieEntries, ...textMatches];
    }

    /**
     * Get autocomplete suggestions for website
     * @param {string} prefix 
     * @param {number} limit 
     * @returns {Array}
     */
    getWebsiteSuggestions(prefix, limit = 5) {
        return this.websiteTrie.autocomplete(prefix.toLowerCase(), limit)
            .map(r => r.word);
    }

    /**
     * Find password by website (O(1) lookup)
     * @param {string} website 
     * @returns {PasswordEntry|null}
     */
    findByWebsite(website) {
        return this.passwordMap.get(website.toLowerCase()) || null;
    }

    // ==========================================
    // Security Analysis (Using DSA)
    // ==========================================

    /**
     * Analyze overall security
     * @returns {Promise<Object>}
     */
    async analyzeSecurityScore() {
        const entries = await this.getAllPasswords();

        if (entries.length === 0) {
            return { score: 100, issues: [], details: {} };
        }

        let score = 100;
        const issues = [];

        // Check password strengths
        const weakPasswords = entries.filter(e => e.strength < 40);
        if (weakPasswords.length > 0) {
            score -= Math.min(30, weakPasswords.length * 5);
            issues.push({
                type: 'weak',
                severity: 'high',
                count: weakPasswords.length,
                message: `${weakPasswords.length} weak password(s) found`
            });
        }

        // Check for old passwords
        const oldPasswords = entries.filter(e => e.isPasswordOld(90));
        if (oldPasswords.length > 0) {
            score -= Math.min(20, oldPasswords.length * 3);
            issues.push({
                type: 'old',
                severity: 'medium',
                count: oldPasswords.length,
                message: `${oldPasswords.length} password(s) older than 90 days`
            });
        }

        // Check for duplicate/similar passwords using Levenshtein
        const decryptedEntries = await Promise.all(
            entries.map(async e => ({
                ...e,
                decryptedPassword: await this.getDecryptedPassword(e.id)
            }))
        );

        const reuseAnalysis = LevenshteinDistance.analyzePasswordReuse(decryptedEntries);
        if (reuseAnalysis.duplicatedGroups.length > 0) {
            score -= Math.min(25, reuseAnalysis.duplicatedGroups.length * 8);
            issues.push({
                type: 'reused',
                severity: 'high',
                count: reuseAnalysis.duplicatedGroups.length,
                message: `${reuseAnalysis.duplicatedGroups.length} reused password(s) detected`
            });
        }

        // Calculate variance score
        const varianceScore = LevenshteinDistance.calculateVarianceScore(decryptedEntries);
        if (varianceScore < 50) {
            score -= 10;
            issues.push({
                type: 'low-variance',
                severity: 'medium',
                message: 'Passwords are too similar to each other'
            });
        }

        return {
            score: Math.max(0, Math.round(score)),
            issues,
            details: {
                totalPasswords: entries.length,
                weakPasswords: weakPasswords.length,
                oldPasswords: oldPasswords.length,
                reuseAnalysis,
                varianceScore
            }
        };
    }

    /**
     * Find duplicate passwords
     * @returns {Promise<Array>}
     */
    async findDuplicates() {
        const entries = await this.getAllPasswords();
        const decrypted = await Promise.all(
            entries.map(async e => ({
                ...e.toJSON(),
                decryptedPassword: await this.getDecryptedPassword(e.id)
            }))
        );

        return LevenshteinDistance.findDuplicateEntries(decrypted, 0.95);
    }

    // ==========================================
    // Password Generation
    // ==========================================

    /**
     * Generate a new password
     * @param {Object} options 
     * @returns {Object}
     */
    generatePassword(options = {}) {
        const password = PasswordGenerator.generate(options);
        const validation = PasswordValidator.validate(password);
        const estimate = PasswordGenerator.estimateStrength(options);

        return {
            password,
            strength: validation,
            estimate
        };
    }

    /**
     * Generate a passphrase
     * @param {Object} options 
     * @returns {string}
     */
    generatePassphrase(options = {}) {
        return PasswordGenerator.generatePassphrase(options);
    }

    // ==========================================
    // Sync Operations
    // ==========================================

    /**
     * Configure sync
     * @param {Object} config 
     */
    configureSync(config) {
        syncService.configure(config);
    }

    /**
     * Sync with server
     * @param {string} direction 
     * @returns {Promise<Object>}
     */
    async sync(direction = 'merge') {
        return await syncService.sync(direction);
    }

    // ==========================================
    // Export/Import
    // ==========================================

    /**
     * Export vault
     * @returns {Promise<string>}
     */
    async exportVault() {
        return await storageService.exportVault();
    }

    /**
     * Import vault
     * @param {string} data 
     * @param {boolean} merge 
     * @returns {Promise<Object>}
     */
    async importVault(data, merge = true) {
        const result = await storageService.importVault(data, merge);
        if (result.success) {
            await this._loadDataStructures();
        }
        return result;
    }

    // ==========================================
    // Private Methods
    // ==========================================

    /**
     * Load entries into DSA data structures
     */
    async _loadDataStructures() {
        const entries = await storageService.getPasswords();

        this.websiteTrie.clear();
        this.passwordMap.clear();
        this.entriesCache = entries;

        for (const entry of entries) {
            this._addToDataStructures(entry);
        }
    }

    /**
     * Add entry to DSA structures
     * @param {PasswordEntry} entry 
     */
    _addToDataStructures(entry) {
        const website = entry.website.toLowerCase();

        // Add to Trie for autocomplete
        this.websiteTrie.insert(website, { id: entry.id });

        // Add to HashMap for O(1) lookup
        this.passwordMap.put(website, entry);

        // Add to cache
        const existingIndex = this.entriesCache.findIndex(e => e.id === entry.id);
        if (existingIndex >= 0) {
            this.entriesCache[existingIndex] = entry;
        } else {
            this.entriesCache.push(entry);
        }
    }
}

// Singleton instance
export const passwordManager = new PasswordManager();
