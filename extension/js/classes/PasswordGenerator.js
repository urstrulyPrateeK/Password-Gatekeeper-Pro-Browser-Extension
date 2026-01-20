/**
 * PasswordGenerator Class
 * Generates secure random passwords with configurable options
 * Uses Web Crypto API for cryptographic randomness
 */

export class PasswordGenerator {
    // Character sets
    static CHARSETS = {
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        numbers: '0123456789',
        symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
        ambiguous: 'iIl1Lo0O',
        similar: '{}[]()/\\\'"`~,;:.<>'
    };

    // Word list for passphrase generation
    static WORDS = [
        'apple', 'beach', 'cloud', 'dance', 'eagle', 'flame', 'grape', 'heart',
        'ivory', 'jewel', 'kayak', 'lemon', 'mango', 'night', 'ocean', 'piano',
        'queen', 'river', 'storm', 'tiger', 'urban', 'vivid', 'whale', 'xenon',
        'yacht', 'zebra', 'alpha', 'brave', 'crisp', 'dream', 'ember', 'frost',
        'globe', 'honey', 'index', 'juice', 'kiwis', 'lunar', 'maple', 'noble',
        'oasis', 'pearl', 'quest', 'roast', 'solar', 'torch', 'ultra', 'vapor',
        'wheat', 'xerox', 'youth', 'zesty', 'bloom', 'charm', 'delta', 'extra'
    ];

    /**
     * Generate a random password
     * @param {Object} options - Generation options
     * @returns {string}
     */
    static generate(options = {}) {
        const defaults = {
            length: 16,
            includeUppercase: true,
            includeLowercase: true,
            includeNumbers: true,
            includeSymbols: true,
            excludeAmbiguous: false,
            excludeSimilar: false,
            customCharset: null,
            beginWithLetter: false
        };

        const config = { ...defaults, ...options };

        // Build character set
        let charset = this._buildCharset(config);

        if (charset.length === 0) {
            throw new Error('No characters available for password generation');
        }

        // Generate password
        let password = '';
        const randomValues = this._getSecureRandomValues(config.length);

        // Ensure first character is a letter if required
        if (config.beginWithLetter) {
            const letterCharset = this.CHARSETS.lowercase +
                (config.includeUppercase ? this.CHARSETS.uppercase : '');
            password += letterCharset[randomValues[0] % letterCharset.length];

            for (let i = 1; i < config.length; i++) {
                password += charset[randomValues[i] % charset.length];
            }
        } else {
            for (let i = 0; i < config.length; i++) {
                password += charset[randomValues[i] % charset.length];
            }
        }

        // Ensure password meets requirements
        password = this._ensureRequirements(password, config, charset);

        return password;
    }

    /**
     * Generate a memorable passphrase
     * @param {Object} options - Generation options
     * @returns {string}
     */
    static generatePassphrase(options = {}) {
        const defaults = {
            wordCount: 4,
            separator: '-',
            capitalize: true,
            includeNumber: true
        };

        const config = { ...defaults, ...options };
        const words = [];
        const randomValues = this._getSecureRandomValues(config.wordCount + 1);

        for (let i = 0; i < config.wordCount; i++) {
            let word = this.WORDS[randomValues[i] % this.WORDS.length];

            if (config.capitalize) {
                word = word.charAt(0).toUpperCase() + word.slice(1);
            }

            words.push(word);
        }

        let passphrase = words.join(config.separator);

        if (config.includeNumber) {
            const num = randomValues[config.wordCount] % 100;
            passphrase += config.separator + num;
        }

        return passphrase;
    }

    /**
     * Generate a PIN code
     * @param {number} length - PIN length
     * @returns {string}
     */
    static generatePIN(length = 4) {
        const randomValues = this._getSecureRandomValues(length);
        let pin = '';

        for (let i = 0; i < length; i++) {
            pin += this.CHARSETS.numbers[randomValues[i] % 10];
        }

        return pin;
    }

    /**
     * Generate multiple password suggestions
     * @param {number} count - Number of passwords to generate
     * @param {Object} options - Generation options
     * @returns {Array<string>}
     */
    static generateMultiple(count = 5, options = {}) {
        const passwords = [];

        for (let i = 0; i < count; i++) {
            passwords.push(this.generate(options));
        }

        return passwords;
    }

    /**
     * Calculate password strength estimate
     * @param {Object} options - Configuration used for generation
     * @returns {Object}
     */
    static estimateStrength(options = {}) {
        let charsetSize = 0;

        if (options.includeLowercase !== false) charsetSize += 26;
        if (options.includeUppercase !== false) charsetSize += 26;
        if (options.includeNumbers !== false) charsetSize += 10;
        if (options.includeSymbols !== false) charsetSize += 32;

        const length = options.length || 16;
        const entropy = length * Math.log2(charsetSize);
        const combinations = Math.pow(charsetSize, length);

        // Time to crack estimation (assuming 10 billion guesses/second)
        const guessesPerSecond = 10e9;
        const secondsToCrack = combinations / guessesPerSecond;

        return {
            entropy: Math.round(entropy),
            charsetSize,
            combinations: combinations.toExponential(2),
            crackTime: this._formatCrackTime(secondsToCrack),
            strength: this._getStrengthLabel(entropy)
        };
    }

    // Private helper methods

    static _buildCharset(config) {
        let charset = config.customCharset || '';

        if (!config.customCharset) {
            if (config.includeLowercase) charset += this.CHARSETS.lowercase;
            if (config.includeUppercase) charset += this.CHARSETS.uppercase;
            if (config.includeNumbers) charset += this.CHARSETS.numbers;
            if (config.includeSymbols) charset += this.CHARSETS.symbols;
        }

        if (config.excludeAmbiguous) {
            for (const char of this.CHARSETS.ambiguous) {
                charset = charset.replace(new RegExp(char, 'g'), '');
            }
        }

        if (config.excludeSimilar) {
            for (const char of this.CHARSETS.similar) {
                charset = charset.replace(new RegExp('\\' + char, 'g'), '');
            }
        }

        return charset;
    }

    static _getSecureRandomValues(length) {
        return crypto.getRandomValues(new Uint32Array(length));
    }

    static _ensureRequirements(password, config, charset) {
        const chars = password.split('');
        let modified = false;

        // Check if password meets all requirements
        const hasLower = config.includeLowercase &&
            /[a-z]/.test(password);
        const hasUpper = config.includeUppercase &&
            /[A-Z]/.test(password);
        const hasNumber = config.includeNumbers &&
            /[0-9]/.test(password);
        const hasSymbol = config.includeSymbols &&
            /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

        const requirements = [];
        if (config.includeLowercase && !hasLower) {
            requirements.push({ needed: true, charset: this.CHARSETS.lowercase });
        }
        if (config.includeUppercase && !hasUpper) {
            requirements.push({ needed: true, charset: this.CHARSETS.uppercase });
        }
        if (config.includeNumbers && !hasNumber) {
            requirements.push({ needed: true, charset: this.CHARSETS.numbers });
        }
        if (config.includeSymbols && !hasSymbol) {
            requirements.push({ needed: true, charset: this.CHARSETS.symbols });
        }

        // Insert missing character types at random positions
        if (requirements.length > 0) {
            const randomValues = this._getSecureRandomValues(requirements.length * 2);
            let rvIndex = 0;

            for (const req of requirements) {
                const charIndex = randomValues[rvIndex++] % req.charset.length;
                const posIndex = randomValues[rvIndex++] % chars.length;
                chars[posIndex] = req.charset[charIndex];
            }

            password = chars.join('');
        }

        return password;
    }

    static _formatCrackTime(seconds) {
        if (seconds < 1) return 'Instant';
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} years`;
        if (seconds < 31536000 * 1000000) return `${Math.round(seconds / (31536000 * 1000))}k years`;
        return 'Centuries+';
    }

    static _getStrengthLabel(entropy) {
        if (entropy >= 128) return 'Excellent';
        if (entropy >= 80) return 'Very Strong';
        if (entropy >= 60) return 'Strong';
        if (entropy >= 40) return 'Moderate';
        if (entropy >= 28) return 'Weak';
        return 'Very Weak';
    }
}
