/**
 * Trie Data Structure for Autocomplete
 * Provides O(m) prefix search where m = query length
 * Used for fast website/account name autocomplete
 */

class TrieNode {
    constructor() {
        this.children = {};
        this.isEndOfWord = false;
        this.data = null; // Store associated password entry
    }
}

export class Trie {
    constructor() {
        this.root = new TrieNode();
        this.size = 0;
    }

    /**
     * Insert a word into the Trie
     * Time Complexity: O(m) where m = word length
     * @param {string} word - The word to insert
     * @param {Object} data - Associated data to store
     */
    insert(word, data = null) {
        if (!word || typeof word !== 'string') return;

        let current = this.root;
        const normalizedWord = word.toLowerCase();

        for (const char of normalizedWord) {
            if (!current.children[char]) {
                current.children[char] = new TrieNode();
            }
            current = current.children[char];
        }

        if (!current.isEndOfWord) {
            this.size++;
        }
        current.isEndOfWord = true;
        current.data = data;
    }

    /**
     * Search for an exact word in the Trie
     * Time Complexity: O(m) where m = word length
     * @param {string} word - The word to search
     * @returns {Object|null} - Associated data or null
     */
    search(word) {
        const node = this._traverseToNode(word);
        return node && node.isEndOfWord ? node.data : null;
    }

    /**
     * Check if any word starts with the given prefix
     * Time Complexity: O(m) where m = prefix length
     * @param {string} prefix - The prefix to check
     * @returns {boolean}
     */
    startsWith(prefix) {
        return this._traverseToNode(prefix) !== null;
    }

    /**
     * Get all words with the given prefix (autocomplete)
     * Time Complexity: O(m + n) where m = prefix length, n = number of results
     * @param {string} prefix - The prefix to search
     * @param {number} limit - Maximum number of results
     * @returns {Array} - Array of matching entries
     */
    autocomplete(prefix, limit = 10) {
        const results = [];
        const node = this._traverseToNode(prefix);

        if (!node) return results;

        this._collectAllWords(node, prefix, results, limit);
        return results;
    }

    /**
     * Delete a word from the Trie
     * Time Complexity: O(m) where m = word length
     * @param {string} word - The word to delete
     * @returns {boolean} - True if word was deleted
     */
    delete(word) {
        return this._deleteHelper(this.root, word.toLowerCase(), 0);
    }

    /**
     * Get all entries in the Trie
     * @returns {Array} - All stored entries
     */
    getAllEntries() {
        const results = [];
        this._collectAllWords(this.root, '', results, Infinity);
        return results;
    }

    /**
     * Clear all entries from the Trie
     */
    clear() {
        this.root = new TrieNode();
        this.size = 0;
    }

    /**
     * Get the number of words in the Trie
     * @returns {number}
     */
    getSize() {
        return this.size;
    }

    // Private helper methods

    _traverseToNode(word) {
        if (!word || typeof word !== 'string') return null;

        let current = this.root;
        const normalizedWord = word.toLowerCase();

        for (const char of normalizedWord) {
            if (!current.children[char]) {
                return null;
            }
            current = current.children[char];
        }

        return current;
    }

    _collectAllWords(node, prefix, results, limit) {
        if (results.length >= limit) return;

        if (node.isEndOfWord) {
            results.push({
                word: prefix,
                data: node.data
            });
        }

        for (const [char, childNode] of Object.entries(node.children)) {
            if (results.length >= limit) break;
            this._collectAllWords(childNode, prefix + char, results, limit);
        }
    }

    _deleteHelper(node, word, index) {
        if (index === word.length) {
            if (!node.isEndOfWord) {
                return false;
            }
            node.isEndOfWord = false;
            node.data = null;
            this.size--;
            return Object.keys(node.children).length === 0;
        }

        const char = word[index];
        const childNode = node.children[char];

        if (!childNode) {
            return false;
        }

        const shouldDeleteChild = this._deleteHelper(childNode, word, index + 1);

        if (shouldDeleteChild) {
            delete node.children[char];
            return !node.isEndOfWord && Object.keys(node.children).length === 0;
        }

        return false;
    }

    /**
     * Serialize the Trie for storage
     * @returns {string} - JSON string representation
     */
    serialize() {
        return JSON.stringify(this._serializeNode(this.root));
    }

    _serializeNode(node) {
        const serialized = {
            children: {},
            isEndOfWord: node.isEndOfWord,
            data: node.data
        };

        for (const [char, childNode] of Object.entries(node.children)) {
            serialized.children[char] = this._serializeNode(childNode);
        }

        return serialized;
    }

    /**
     * Deserialize from stored data
     * @param {string} jsonString - JSON string to deserialize
     */
    static deserialize(jsonString) {
        const trie = new Trie();
        try {
            const data = JSON.parse(jsonString);
            trie.root = trie._deserializeNode(data);
            trie._recalculateSize();
        } catch (e) {
            console.error('Failed to deserialize Trie:', e);
        }
        return trie;
    }

    _deserializeNode(data) {
        const node = new TrieNode();
        node.isEndOfWord = data.isEndOfWord;
        node.data = data.data;

        for (const [char, childData] of Object.entries(data.children)) {
            node.children[char] = this._deserializeNode(childData);
        }

        return node;
    }

    _recalculateSize() {
        this.size = 0;
        this._countWords(this.root);
    }

    _countWords(node) {
        if (node.isEndOfWord) {
            this.size++;
        }
        for (const childNode of Object.values(node.children)) {
            this._countWords(childNode);
        }
    }
}
