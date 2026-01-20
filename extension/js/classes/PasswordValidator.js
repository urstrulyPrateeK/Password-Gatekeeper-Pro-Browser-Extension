/**
 * PasswordValidator Class
 * Validates password strength with detailed analysis
 * Ported from Python with enhanced features
 */

export class PasswordValidator {
    // Common passwords list (subset for extension size)
    static COMMON_PASSWORDS = new Set([
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
        'master', 'dragon', 'letmein', 'login', 'admin', 'welcome',
        'password1', 'password123', 'iloveyou', 'sunshine', 'princess',
        'football', 'baseball', 'superman', 'michael', 'shadow', 'ashley'
    ]);

    // Character patterns for strength calculation
    static PATTERNS = {
        lowercase: /[a-z]/,
        uppercase: /[A-Z]/,
        digit: /[0-9]/,
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/,
        whitespace: /\s/,
        sequential: /(.)\1{2,}/,
        keyboard: /(qwerty|asdf|zxcv|1234|0987)/i
    };

    /**
     * Validate password and return detailed analysis
     * @param {string} password - Password to validate
     * @returns {Object} - Detailed validation result
     */
    static validate(password) {
        if (!password || typeof password !== 'string') {
            return {
                score: 0,
                strength: 'invalid',
                label: 'Invalid Password',
                details: {
                    length: 0,
                    hasLowercase: false,
                    hasUppercase: false,
                    hasDigit: false,
                    hasSpecial: false,
                    hasWhitespace: false
                },
                suggestions: ['Enter a password']
            };
        }

        // Check for whitespace
        if (this.PATTERNS.whitespace.test(password)) {
            return {
                score: 0,
                strength: 'invalid',
                label: 'Invalid Password',
                details: { hasWhitespace: true },
                suggestions: ['Remove spaces from password']
            };
        }

        // Calculate score based on various factors
        let score = 0;
        const details = this._analyzePassword(password);
        const suggestions = [];

        // Length scoring (up to 30 points)
        if (details.length >= 8) score += 10;
        if (details.length >= 12) score += 10;
        if (details.length >= 16) score += 10;

        // Character variety scoring (up to 40 points)
        if (details.hasLowercase) score += 10;
        if (details.hasUppercase) score += 10;
        if (details.hasDigit) score += 10;
        if (details.hasSpecial) score += 10;

        // Bonus for length beyond 16 (up to 10 points)
        score += Math.min(10, Math.floor((details.length - 16) / 2) * 2);

        // Entropy bonus (up to 20 points)
        const entropy = this._calculateEntropy(password);
        score += Math.min(20, Math.floor(entropy / 3));

        // Penalties
        if (this._isCommonPassword(password)) {
            score = Math.max(0, score - 50);
            suggestions.push('Avoid common passwords');
        }

        if (this.PATTERNS.sequential.test(password)) {
            score = Math.max(0, score - 10);
            suggestions.push('Avoid repeated characters');
        }

        if (this.PATTERNS.keyboard.test(password)) {
            score = Math.max(0, score - 10);
            suggestions.push('Avoid keyboard patterns');
        }

        // Generate suggestions
        if (details.length < 8) suggestions.push('Use at least 8 characters');
        if (details.length < 12) suggestions.push('Consider using 12+ characters');
        if (!details.hasLowercase) suggestions.push('Add lowercase letters');
        if (!details.hasUppercase) suggestions.push('Add uppercase letters');
        if (!details.hasDigit) suggestions.push('Add numbers');
        if (!details.hasSpecial) suggestions.push('Add special characters');

        // Normalize score to 0-100
        score = Math.min(100, Math.max(0, score));

        // Determine strength category
        const { strength, label } = this._categorizeStrength(score);

        return {
            score,
            strength,
            label,
            details,
            entropy,
            suggestions
        };
    }

    /**
     * Quick strength check (returns simple label)
     * Matches the original Python implementation
     * @param {string} password 
     * @returns {string}
     */
    static checkStrength(password) {
        if (!password || password.length < 8) {
            return 'Weak Password';
        }

        if (this.PATTERNS.whitespace.test(password)) {
            return 'Invalid Password';
        }

        let hasUpper = false;
        let hasLower = false;
        let hasDigit = false;
        let hasSpecial = false;

        for (const ch of password) {
            if (ch >= 'A' && ch <= 'Z') hasUpper = true;
            else if (ch >= 'a' && ch <= 'z') hasLower = true;
            else if (ch >= '0' && ch <= '9') hasDigit = true;
            else hasSpecial = true;
        }

        if (hasUpper && hasLower && hasDigit && hasSpecial) {
            return 'Strong Password';
        }

        if ((hasUpper || hasLower) && hasDigit) {
            return 'Medium Password';
        }

        return 'Weak Password';
    }

    /**
     * Get numeric score for sorting/comparison
     * @param {string} password 
     * @returns {number} 0-100
     */
    static getScore(password) {
        return this.validate(password).score;
    }

    /**
     * Check if password meets minimum requirements
     * @param {string} password 
     * @param {Object} requirements 
     * @returns {Object}
     */
    static meetsRequirements(password, requirements = {}) {
        const defaults = {
            minLength: 8,
            requireUppercase: true,
            requireLowercase: true,
            requireDigit: true,
            requireSpecial: true,
            minScore: 50
        };

        const reqs = { ...defaults, ...requirements };
        const result = this.validate(password);
        const issues = [];

        if (result.details.length < reqs.minLength) {
            issues.push(`Minimum length: ${reqs.minLength}`);
        }
        if (reqs.requireUppercase && !result.details.hasUppercase) {
            issues.push('Uppercase letter required');
        }
        if (reqs.requireLowercase && !result.details.hasLowercase) {
            issues.push('Lowercase letter required');
        }
        if (reqs.requireDigit && !result.details.hasDigit) {
            issues.push('Number required');
        }
        if (reqs.requireSpecial && !result.details.hasSpecial) {
            issues.push('Special character required');
        }
        if (result.score < reqs.minScore) {
            issues.push(`Minimum strength: ${reqs.minScore}%`);
        }

        return {
            meets: issues.length === 0,
            issues
        };
    }

    // Private helper methods

    static _analyzePassword(password) {
        return {
            length: password.length,
            hasLowercase: this.PATTERNS.lowercase.test(password),
            hasUppercase: this.PATTERNS.uppercase.test(password),
            hasDigit: this.PATTERNS.digit.test(password),
            hasSpecial: this.PATTERNS.special.test(password),
            hasWhitespace: this.PATTERNS.whitespace.test(password),
            hasSequential: this.PATTERNS.sequential.test(password),
            hasKeyboardPattern: this.PATTERNS.keyboard.test(password)
        };
    }

    static _calculateEntropy(password) {
        // Calculate character set size
        let charsetSize = 0;
        if (this.PATTERNS.lowercase.test(password)) charsetSize += 26;
        if (this.PATTERNS.uppercase.test(password)) charsetSize += 26;
        if (this.PATTERNS.digit.test(password)) charsetSize += 10;
        if (this.PATTERNS.special.test(password)) charsetSize += 32;

        if (charsetSize === 0) return 0;

        // Entropy = length * log2(charset size)
        return password.length * Math.log2(charsetSize);
    }

    static _isCommonPassword(password) {
        return this.COMMON_PASSWORDS.has(password.toLowerCase());
    }

    static _categorizeStrength(score) {
        if (score >= 80) return { strength: 'strong', label: 'Strong Password' };
        if (score >= 60) return { strength: 'good', label: 'Good Password' };
        if (score >= 40) return { strength: 'fair', label: 'Fair Password' };
        if (score >= 20) return { strength: 'weak', label: 'Weak Password' };
        return { strength: 'very-weak', label: 'Very Weak Password' };
    }

    /**
     * Get color for strength visualization
     * @param {string} strength 
     * @returns {string}
     */
    static getStrengthColor(strength) {
        const colors = {
            'strong': '#22c55e',    // Green
            'good': '#84cc16',      // Lime
            'fair': '#f59e0b',      // Amber
            'weak': '#f97316',      // Orange
            'very-weak': '#ef4444', // Red
            'invalid': '#6b7280'    // Gray
        };
        return colors[strength] || colors['invalid'];
    }

    /**
     * Get CSS class for strength
     * @param {number} score 
     * @returns {string}
     */
    static getStrengthClass(score) {
        if (score >= 80) return 'strong';
        if (score >= 60) return 'good';
        if (score >= 40) return 'fair';
        return 'weak';
    }
}
