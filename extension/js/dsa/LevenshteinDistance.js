/**
 * Levenshtein Distance Algorithm
 * Used for detecting similar/duplicate passwords
 * Time Complexity: O(m * n) where m, n are string lengths
 */

export class LevenshteinDistance {
    /**
     * Calculate Levenshtein distance between two strings
     * Time Complexity: O(m * n)
     * Space Complexity: O(min(m, n)) - optimized
     * @param {string} str1 - First string
     * @param {string} str2 - Second string
     * @returns {number} - Edit distance
     */
    static calculate(str1, str2) {
        if (!str1 || str1.length === 0) return str2 ? str2.length : 0;
        if (!str2 || str2.length === 0) return str1.length;

        // Ensure str1 is the shorter string for space optimization
        if (str1.length > str2.length) {
            [str1, str2] = [str2, str1];
        }

        const m = str1.length;
        const n = str2.length;

        // Use two rows instead of full matrix for space optimization
        let previousRow = new Array(m + 1);
        let currentRow = new Array(m + 1);

        // Initialize first row
        for (let i = 0; i <= m; i++) {
            previousRow[i] = i;
        }

        // Fill in the rest of the matrix
        for (let j = 1; j <= n; j++) {
            currentRow[0] = j;

            for (let i = 1; i <= m; i++) {
                const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;

                currentRow[i] = Math.min(
                    previousRow[i] + 1,      // Deletion
                    currentRow[i - 1] + 1,   // Insertion
                    previousRow[i - 1] + cost // Substitution
                );
            }

            // Swap rows
            [previousRow, currentRow] = [currentRow, previousRow];
        }

        return previousRow[m];
    }

    /**
     * Calculate similarity ratio (0 to 1)
     * @param {string} str1 - First string
     * @param {string} str2 - Second string
     * @returns {number} - Similarity ratio (1 = identical, 0 = completely different)
     */
    static similarity(str1, str2) {
        if (!str1 && !str2) return 1;
        if (!str1 || !str2) return 0;

        const maxLen = Math.max(str1.length, str2.length);
        if (maxLen === 0) return 1;

        const distance = this.calculate(str1, str2);
        return 1 - (distance / maxLen);
    }

    /**
     * Check if two strings are similar within a threshold
     * @param {string} str1 - First string
     * @param {string} str2 - Second string
     * @param {number} threshold - Similarity threshold (0 to 1)
     * @returns {boolean}
     */
    static isSimilar(str1, str2, threshold = 0.7) {
        return this.similarity(str1, str2) >= threshold;
    }

    /**
     * Find similar passwords in a collection
     * @param {string} password - Password to compare
     * @param {Array} passwords - Array of passwords to check against
     * @param {number} threshold - Similarity threshold
     * @returns {Array} - Similar passwords with their similarity scores
     */
    static findSimilarPasswords(password, passwords, threshold = 0.7) {
        const results = [];

        for (const pwd of passwords) {
            if (password === pwd) continue; // Skip exact matches

            const similarity = this.similarity(password, pwd);
            if (similarity >= threshold) {
                results.push({
                    password: pwd,
                    similarity: similarity,
                    distance: this.calculate(password, pwd)
                });
            }
        }

        // Sort by similarity (highest first)
        return results.sort((a, b) => b.similarity - a.similarity);
    }

    /**
     * Find duplicate/similar password entries
     * @param {Array} entries - Password entries with 'password' field
     * @param {number} threshold - Similarity threshold
     * @returns {Array} - Groups of similar passwords
     */
    static findDuplicateEntries(entries, threshold = 0.85) {
        const groups = [];
        const processed = new Set();

        for (let i = 0; i < entries.length; i++) {
            if (processed.has(i)) continue;

            const group = [entries[i]];
            processed.add(i);

            for (let j = i + 1; j < entries.length; j++) {
                if (processed.has(j)) continue;

                const similarity = this.similarity(
                    entries[i].password || entries[i].decryptedPassword || '',
                    entries[j].password || entries[j].decryptedPassword || ''
                );

                if (similarity >= threshold) {
                    group.push({
                        ...entries[j],
                        similarity: similarity
                    });
                    processed.add(j);
                }
            }

            if (group.length > 1) {
                groups.push(group);
            }
        }

        return groups;
    }

    /**
     * Detect password reuse across different websites
     * @param {Array} entries - Password entries
     * @returns {Object} - Analysis of password reuse
     */
    static analyzePasswordReuse(entries) {
        const exactDuplicates = new Map();
        const similarPasswords = [];
        const uniquePasswords = new Set();

        // First pass: find exact duplicates
        for (const entry of entries) {
            const pwd = entry.password || entry.decryptedPassword || '';
            if (!pwd) continue;

            if (exactDuplicates.has(pwd)) {
                exactDuplicates.get(pwd).push(entry);
            } else {
                exactDuplicates.set(pwd, [entry]);
            }
            uniquePasswords.add(pwd);
        }

        // Filter to only duplicated passwords
        const duplicatedGroups = [];
        exactDuplicates.forEach((entries, password) => {
            if (entries.length > 1) {
                duplicatedGroups.push({
                    type: 'exact',
                    count: entries.length,
                    websites: entries.map(e => e.website)
                });
            }
        });

        // Second pass: find similar passwords
        const passwords = Array.from(uniquePasswords);
        for (let i = 0; i < passwords.length; i++) {
            for (let j = i + 1; j < passwords.length; j++) {
                const similarity = this.similarity(passwords[i], passwords[j]);
                if (similarity >= 0.7 && similarity < 1) {
                    similarPasswords.push({
                        similarity: Math.round(similarity * 100),
                        password1: passwords[i].substring(0, 3) + '***',
                        password2: passwords[j].substring(0, 3) + '***'
                    });
                }
            }
        }

        return {
            totalEntries: entries.length,
            uniquePasswords: uniquePasswords.size,
            duplicatedGroups: duplicatedGroups,
            similarPasswords: similarPasswords,
            reusePercentage: entries.length > 0
                ? Math.round((1 - uniquePasswords.size / entries.length) * 100)
                : 0
        };
    }

    /**
     * Calculate password variance score
     * Higher score = more unique passwords used
     * @param {Array} entries - Password entries
     * @returns {number} - Variance score (0-100)
     */
    static calculateVarianceScore(entries) {
        if (!entries || entries.length === 0) return 100;
        if (entries.length === 1) return 100;

        const passwords = entries
            .map(e => e.password || e.decryptedPassword || '')
            .filter(p => p.length > 0);

        if (passwords.length <= 1) return 100;

        let totalSimilarity = 0;
        let comparisons = 0;

        for (let i = 0; i < passwords.length; i++) {
            for (let j = i + 1; j < passwords.length; j++) {
                totalSimilarity += this.similarity(passwords[i], passwords[j]);
                comparisons++;
            }
        }

        const avgSimilarity = comparisons > 0 ? totalSimilarity / comparisons : 0;

        // Invert: high similarity = low variance
        return Math.round((1 - avgSimilarity) * 100);
    }
}
