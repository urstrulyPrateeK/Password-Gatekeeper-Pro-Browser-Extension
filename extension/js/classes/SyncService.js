/**
 * SyncService Class
 * Manages synchronization with encrypted API backend
 * Handles JWT authentication and encrypted data transfer
 */

import { cryptoService } from './CryptoService.js';
import { storageService } from './StorageService.js';
import { PasswordEntry } from './PasswordEntry.js';

export class SyncService {
    #apiUrl = '';
    #accessToken = null;
    #refreshToken = null;
    #tokenExpiry = null;

    constructor() {
        this.isSyncing = false;
        this.lastSyncTime = null;
    }

    /**
     * Configure the sync service
     * @param {Object} config 
     */
    configure(config) {
        this.#apiUrl = config.apiUrl || '';
        if (config.accessToken) this.#accessToken = config.accessToken;
        if (config.refreshToken) this.#refreshToken = config.refreshToken;
    }

    /**
     * Check if sync is configured
     * @returns {boolean}
     */
    isConfigured() {
        return this.#apiUrl && this.#apiUrl.length > 0;
    }

    /**
     * Test connection to API server
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async testConnection() {
        if (!this.#apiUrl) {
            return { success: false, message: 'API URL not configured' };
        }

        try {
            const response = await fetch(`${this.#apiUrl}/api/health`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' }
            });

            if (response.ok) {
                return { success: true, message: 'Connection successful' };
            } else {
                return { success: false, message: `Server error: ${response.status}` };
            }
        } catch (error) {
            return { success: false, message: `Connection failed: ${error.message}` };
        }
    }

    /**
     * Register a new account
     * @param {string} email 
     * @param {string} password 
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async register(email, password) {
        try {
            // Hash password before sending
            const hashedPassword = await cryptoService.hashPassword(password);

            const response = await this._request('/api/auth/register', {
                method: 'POST',
                body: JSON.stringify({ email, password: hashedPassword })
            });

            if (response.success) {
                return { success: true, message: 'Registration successful' };
            } else {
                return { success: false, message: response.error || 'Registration failed' };
            }
        } catch (error) {
            return { success: false, message: error.message };
        }
    }

    /**
     * Login to sync server
     * @param {string} email 
     * @param {string} password 
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async login(email, password) {
        try {
            const hashedPassword = await cryptoService.hashPassword(password);

            const response = await this._request('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify({ email, password: hashedPassword })
            });

            if (response.success && response.access_token) {
                this.#accessToken = response.access_token;
                this.#refreshToken = response.refresh_token;
                this.#tokenExpiry = Date.now() + (response.expires_in * 1000);

                // Store tokens securely
                await this._storeTokens();

                return { success: true, message: 'Login successful' };
            } else {
                return { success: false, message: response.error || 'Login failed' };
            }
        } catch (error) {
            return { success: false, message: error.message };
        }
    }

    /**
     * Logout from sync server
     */
    async logout() {
        this.#accessToken = null;
        this.#refreshToken = null;
        this.#tokenExpiry = null;
        await storageService.remove('sync_tokens');
    }

    /**
     * Check if authenticated
     * @returns {boolean}
     */
    isAuthenticated() {
        return this.#accessToken !== null &&
            (this.#tokenExpiry === null || Date.now() < this.#tokenExpiry);
    }

    /**
     * Sync passwords with server
     * @param {string} direction - 'push', 'pull', or 'merge'
     * @returns {Promise<{success: boolean, message: string, stats: Object}>}
     */
    async sync(direction = 'merge') {
        if (!this.isConfigured()) {
            return { success: false, message: 'Sync not configured' };
        }

        if (!this.isAuthenticated()) {
            return { success: false, message: 'Not authenticated' };
        }

        if (this.isSyncing) {
            return { success: false, message: 'Sync already in progress' };
        }

        this.isSyncing = true;

        try {
            const localEntries = await storageService.getPasswords();
            const stats = { pushed: 0, pulled: 0, conflicts: 0 };

            if (direction === 'push' || direction === 'merge') {
                // Encrypt and upload local entries
                const encryptedEntries = [];
                for (const entry of localEntries) {
                    const encrypted = await cryptoService.encrypt(JSON.stringify(entry.toJSON()));
                    encryptedEntries.push({
                        id: entry.id,
                        data: encrypted,
                        updatedAt: entry.updatedAt
                    });
                }

                const pushResponse = await this._authenticatedRequest('/api/passwords/sync', {
                    method: 'POST',
                    body: JSON.stringify({ entries: encryptedEntries })
                });

                if (pushResponse.success) {
                    stats.pushed = pushResponse.pushed || 0;
                }
            }

            if (direction === 'pull' || direction === 'merge') {
                // Download and decrypt server entries
                const pullResponse = await this._authenticatedRequest('/api/passwords', {
                    method: 'GET'
                });

                if (pullResponse.success && pullResponse.entries) {
                    const serverEntries = [];

                    for (const encEntry of pullResponse.entries) {
                        try {
                            const decrypted = await cryptoService.decrypt(encEntry.data);
                            const entry = PasswordEntry.fromJSON(JSON.parse(decrypted));
                            serverEntries.push(entry);
                        } catch (e) {
                            console.error('Failed to decrypt server entry:', e);
                        }
                    }

                    if (direction === 'merge') {
                        // Merge logic: newer entries win
                        const merged = this._mergeEntries(localEntries, serverEntries, stats);
                        await storageService.savePasswords(merged);
                    } else {
                        // Pull: replace local with server
                        await storageService.savePasswords(serverEntries);
                        stats.pulled = serverEntries.length;
                    }
                }
            }

            this.lastSyncTime = new Date();
            await storageService.set('last_sync', this.lastSyncTime.toISOString());

            return {
                success: true,
                message: 'Sync completed successfully',
                stats
            };
        } catch (error) {
            return {
                success: false,
                message: `Sync failed: ${error.message}`,
                stats: {}
            };
        } finally {
            this.isSyncing = false;
        }
    }

    /**
     * Get last sync time
     * @returns {Promise<Date|null>}
     */
    async getLastSyncTime() {
        const lastSync = await storageService.get('last_sync');
        return lastSync ? new Date(lastSync) : null;
    }

    // Private methods

    async _request(endpoint, options = {}) {
        const url = `${this.#apiUrl}${endpoint}`;
        const defaultHeaders = {
            'Content-Type': 'application/json'
        };

        const response = await fetch(url, {
            ...options,
            headers: { ...defaultHeaders, ...options.headers }
        });

        return await response.json();
    }

    async _authenticatedRequest(endpoint, options = {}) {
        if (!this.isAuthenticated()) {
            // Try to refresh token
            const refreshed = await this._refreshAccessToken();
            if (!refreshed) {
                throw new Error('Authentication required');
            }
        }

        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${this.#accessToken}`
        };

        return await this._request(endpoint, { ...options, headers });
    }

    async _refreshAccessToken() {
        if (!this.#refreshToken) {
            return false;
        }

        try {
            const response = await this._request('/api/auth/refresh', {
                method: 'POST',
                body: JSON.stringify({ refresh_token: this.#refreshToken })
            });

            if (response.success && response.access_token) {
                this.#accessToken = response.access_token;
                this.#tokenExpiry = Date.now() + (response.expires_in * 1000);
                await this._storeTokens();
                return true;
            }
        } catch (error) {
            console.error('Token refresh failed:', error);
        }

        return false;
    }

    async _storeTokens() {
        await storageService.set('sync_tokens', {
            accessToken: this.#accessToken,
            refreshToken: this.#refreshToken,
            tokenExpiry: this.#tokenExpiry
        });
    }

    async loadTokens() {
        const tokens = await storageService.get('sync_tokens');
        if (tokens) {
            this.#accessToken = tokens.accessToken;
            this.#refreshToken = tokens.refreshToken;
            this.#tokenExpiry = tokens.tokenExpiry;
        }
    }

    _mergeEntries(localEntries, serverEntries, stats) {
        const merged = new Map();

        // Add all local entries
        for (const entry of localEntries) {
            merged.set(entry.id, entry);
        }

        // Merge server entries
        for (const serverEntry of serverEntries) {
            const local = merged.get(serverEntry.id);

            if (!local) {
                // New from server
                merged.set(serverEntry.id, serverEntry);
                stats.pulled++;
            } else {
                // Conflict - use newer
                const localTime = new Date(local.updatedAt).getTime();
                const serverTime = new Date(serverEntry.updatedAt).getTime();

                if (serverTime > localTime) {
                    merged.set(serverEntry.id, serverEntry);
                    stats.conflicts++;
                }
            }
        }

        return Array.from(merged.values());
    }
}

// Singleton instance
export const syncService = new SyncService();
