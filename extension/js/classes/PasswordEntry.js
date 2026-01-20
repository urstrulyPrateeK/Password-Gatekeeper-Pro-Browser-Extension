/**
 * PasswordEntry Class - Data Model
 * Represents a single password entry in the vault
 * OOP Implementation with encapsulation
 */

export class PasswordEntry {
    #id;
    #encryptedPassword;
    #createdAt;
    #updatedAt;

    constructor({
        id = null,
        website = '',
        username = '',
        encryptedPassword = '',
        notes = '',
        tags = [],
        createdAt = null,
        updatedAt = null,
        strength = 0,
        favicon = null
    } = {}) {
        this.#id = id || this._generateId();
        this.website = website;
        this.username = username;
        this.#encryptedPassword = encryptedPassword;
        this.notes = notes;
        this.tags = Array.isArray(tags) ? tags : [];
        this.#createdAt = createdAt || new Date().toISOString();
        this.#updatedAt = updatedAt || this.#createdAt;
        this.strength = strength;
        this.favicon = favicon;
    }

    // Getters
    get id() {
        return this.#id;
    }

    get encryptedPassword() {
        return this.#encryptedPassword;
    }

    get createdAt() {
        return this.#createdAt;
    }

    get updatedAt() {
        return this.#updatedAt;
    }

    // Setters with validation
    set encryptedPassword(value) {
        if (typeof value !== 'string') {
            throw new Error('Encrypted password must be a string');
        }
        this.#encryptedPassword = value;
        this._updateTimestamp();
    }

    setWebsite(value) {
        if (!value || typeof value !== 'string') {
            throw new Error('Website is required and must be a string');
        }
        this.website = value.toLowerCase().trim();
        this._updateTimestamp();
    }

    setUsername(value) {
        if (typeof value !== 'string') {
            throw new Error('Username must be a string');
        }
        this.username = value.trim();
        this._updateTimestamp();
    }

    setNotes(value) {
        this.notes = value || '';
        this._updateTimestamp();
    }

    setTags(value) {
        if (!Array.isArray(value)) {
            throw new Error('Tags must be an array');
        }
        this.tags = value.map(tag => tag.trim().toLowerCase());
        this._updateTimestamp();
    }

    addTag(tag) {
        const normalizedTag = tag.trim().toLowerCase();
        if (!this.tags.includes(normalizedTag)) {
            this.tags.push(normalizedTag);
            this._updateTimestamp();
        }
    }

    removeTag(tag) {
        const normalizedTag = tag.trim().toLowerCase();
        const index = this.tags.indexOf(normalizedTag);
        if (index > -1) {
            this.tags.splice(index, 1);
            this._updateTimestamp();
        }
    }

    // Private methods
    _generateId() {
        return 'pwd_' + Date.now().toString(36) + '_' +
            Math.random().toString(36).substring(2, 11);
    }

    _updateTimestamp() {
        this.#updatedAt = new Date().toISOString();
    }

    // Get initial letter for avatar
    getInitial() {
        if (this.website) {
            const domain = this.extractDomain();
            return domain.charAt(0).toUpperCase();
        }
        return '?';
    }

    // Extract domain from website
    extractDomain() {
        try {
            let url = this.website;
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                url = 'https://' + url;
            }
            const urlObj = new URL(url);
            return urlObj.hostname.replace('www.', '');
        } catch {
            return this.website;
        }
    }

    // Check if entry matches search query
    matches(query) {
        if (!query) return true;

        const lowerQuery = query.toLowerCase();
        return (
            this.website.toLowerCase().includes(lowerQuery) ||
            this.username.toLowerCase().includes(lowerQuery) ||
            this.notes.toLowerCase().includes(lowerQuery) ||
            this.tags.some(tag => tag.includes(lowerQuery))
        );
    }

    // Check if entry has specific tag
    hasTag(tag) {
        return this.tags.includes(tag.toLowerCase().trim());
    }

    // Get age of password in days
    getPasswordAge() {
        const created = new Date(this.#createdAt);
        const now = new Date();
        const diffTime = Math.abs(now - created);
        return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    }

    // Check if password is old (> 90 days)
    isPasswordOld(thresholdDays = 90) {
        return this.getPasswordAge() > thresholdDays;
    }

    // Clone the entry
    clone() {
        return new PasswordEntry({
            id: this.#id,
            website: this.website,
            username: this.username,
            encryptedPassword: this.#encryptedPassword,
            notes: this.notes,
            tags: [...this.tags],
            createdAt: this.#createdAt,
            updatedAt: this.#updatedAt,
            strength: this.strength,
            favicon: this.favicon
        });
    }

    // Convert to plain object for storage
    toJSON() {
        return {
            id: this.#id,
            website: this.website,
            username: this.username,
            encryptedPassword: this.#encryptedPassword,
            notes: this.notes,
            tags: this.tags,
            createdAt: this.#createdAt,
            updatedAt: this.#updatedAt,
            strength: this.strength,
            favicon: this.favicon
        };
    }

    // Create from plain object
    static fromJSON(data) {
        return new PasswordEntry({
            id: data.id,
            website: data.website,
            username: data.username,
            encryptedPassword: data.encryptedPassword,
            notes: data.notes,
            tags: data.tags,
            createdAt: data.createdAt,
            updatedAt: data.updatedAt,
            strength: data.strength,
            favicon: data.favicon
        });
    }

    // Create multiple entries from JSON array
    static fromJSONArray(dataArray) {
        if (!Array.isArray(dataArray)) return [];
        return dataArray.map(data => PasswordEntry.fromJSON(data));
    }

    // Compare entries for sorting
    static compare(a, b, field = 'website') {
        switch (field) {
            case 'website':
                return a.website.localeCompare(b.website);
            case 'username':
                return a.username.localeCompare(b.username);
            case 'createdAt':
                return new Date(b.createdAt) - new Date(a.createdAt);
            case 'updatedAt':
                return new Date(b.updatedAt) - new Date(a.updatedAt);
            case 'strength':
                return b.strength - a.strength;
            default:
                return 0;
        }
    }

    // Validate entry data
    validate() {
        const errors = [];

        if (!this.website || this.website.trim() === '') {
            errors.push('Website is required');
        }

        if (!this.username || this.username.trim() === '') {
            errors.push('Username is required');
        }

        if (!this.#encryptedPassword || this.#encryptedPassword.trim() === '') {
            errors.push('Password is required');
        }

        return {
            isValid: errors.length === 0,
            errors: errors
        };
    }

    // String representation
    toString() {
        return `PasswordEntry(${this.website} - ${this.username})`;
    }
}
