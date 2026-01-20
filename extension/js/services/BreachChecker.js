/**
 * BreachChecker Service
 * Checks passwords against Have I Been Pwned API using k-Anonymity
 * Ensures password privacy by only sending first 5 characters of SHA-1 hash
 */

export class BreachChecker {
    static API_BASE = 'https://api.pwnedpasswords.com/range';

    /**
     * Check if a password has been breached
     * Uses k-Anonymity model - only first 5 chars of SHA-1 sent
     * @param {string} password - The password to check
     * @returns {Promise<{breached: boolean, count: number}>}
     */
    static async checkPassword(password) {
        if (!password) {
            return { breached: false, count: 0 };
        }

        try {
            // Calculate SHA-1 hash of password
            const hash = await this._sha1(password);
            const prefix = hash.substring(0, 5).toUpperCase();
            const suffix = hash.substring(5).toUpperCase();

            // Query HIBP API with prefix only (k-Anonymity)
            const response = await fetch(`${this.API_BASE}/${prefix}`, {
                headers: {
                    'Add-Padding': 'true' // Adds padding to prevent timing attacks
                }
            });

            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            const text = await response.text();

            // Parse response and find our suffix
            const lines = text.split('\r\n');
            for (const line of lines) {
                const [hashSuffix, count] = line.split(':');
                if (hashSuffix === suffix) {
                    return {
                        breached: true,
                        count: parseInt(count, 10)
                    };
                }
            }

            return { breached: false, count: 0 };
        } catch (error) {
            console.error('Breach check failed:', error);
            return { breached: false, count: 0, error: error.message };
        }
    }

    /**
     * Check multiple passwords for breaches
     * @param {Array<{id: string, password: string}>} entries 
     * @returns {Promise<Array<{id: string, breached: boolean, count: number}>>}
     */
    static async checkMultiple(entries) {
        const results = [];

        // Process in batches to avoid rate limiting
        const batchSize = 5;
        for (let i = 0; i < entries.length; i += batchSize) {
            const batch = entries.slice(i, i + batchSize);

            const batchResults = await Promise.all(
                batch.map(async entry => {
                    const result = await this.checkPassword(entry.password);
                    return {
                        id: entry.id,
                        ...result
                    };
                })
            );

            results.push(...batchResults);

            // Rate limiting: wait 1.5 seconds between batches
            if (i + batchSize < entries.length) {
                await new Promise(resolve => setTimeout(resolve, 1500));
            }
        }

        return results;
    }

    /**
     * Get breach statistics for a password vault
     * @param {Array<{id: string, password: string}>} entries 
     * @returns {Promise<Object>}
     */
    static async analyzeVault(entries) {
        const results = await this.checkMultiple(entries);

        const breached = results.filter(r => r.breached);
        const totalBreaches = breached.reduce((sum, r) => sum + r.count, 0);

        return {
            totalChecked: entries.length,
            breachedCount: breached.length,
            safeCount: entries.length - breached.length,
            breachedEntries: breached,
            totalExposures: totalBreaches,
            safetyScore: entries.length > 0
                ? Math.round((1 - breached.length / entries.length) * 100)
                : 100
        };
    }

    /**
     * Calculate SHA-1 hash using Web Crypto API
     * @param {string} message 
     * @returns {Promise<string>}
     */
    static async _sha1(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Get breach severity level
     * @param {number} count - Number of times breached
     * @returns {Object}
     */
    static getBreachSeverity(count) {
        if (count === 0) {
            return { level: 'safe', label: 'Safe', color: '#22c55e' };
        } else if (count < 100) {
            return { level: 'low', label: 'Low Risk', color: '#f59e0b' };
        } else if (count < 10000) {
            return { level: 'medium', label: 'Medium Risk', color: '#f97316' };
        } else {
            return { level: 'high', label: 'High Risk', color: '#ef4444' };
        }
    }

    /**
     * Format breach count for display
     * @param {number} count 
     * @returns {string}
     */
    static formatBreachCount(count) {
        if (count >= 1000000) {
            return `${(count / 1000000).toFixed(1)}M`;
        } else if (count >= 1000) {
            return `${(count / 1000).toFixed(1)}K`;
        }
        return count.toString();
    }
}
