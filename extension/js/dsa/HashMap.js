/**
 * Custom HashMap Implementation
 * Provides O(1) average case lookups with collision handling via chaining
 * Used for fast password lookups by website
 */

class HashNode {
    constructor(key, value) {
        this.key = key;
        this.value = value;
        this.next = null;
    }
}

export class HashMap {
    constructor(initialCapacity = 16, loadFactor = 0.75) {
        this.capacity = initialCapacity;
        this.loadFactor = loadFactor;
        this.size = 0;
        this.buckets = new Array(this.capacity).fill(null);
    }

    /**
     * Hash function using djb2 algorithm
     * Time Complexity: O(k) where k = key length
     * @param {string} key - The key to hash
     * @returns {number} - Hash value
     */
    _hash(key) {
        let hash = 5381;
        const str = String(key);

        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) + hash) + str.charCodeAt(i);
            hash = hash & hash; // Convert to 32-bit integer
        }

        return Math.abs(hash % this.capacity);
    }

    /**
     * Put a key-value pair into the HashMap
     * Time Complexity: O(1) average, O(n) worst case
     * @param {string} key - The key
     * @param {*} value - The value to store
     */
    put(key, value) {
        if (key === null || key === undefined) return;

        // Check if resize is needed
        if ((this.size + 1) / this.capacity > this.loadFactor) {
            this._resize();
        }

        const index = this._hash(key);
        let node = this.buckets[index];

        // Check if key already exists
        while (node !== null) {
            if (node.key === key) {
                node.value = value; // Update existing
                return;
            }
            node = node.next;
        }

        // Insert new node at head of chain
        const newNode = new HashNode(key, value);
        newNode.next = this.buckets[index];
        this.buckets[index] = newNode;
        this.size++;
    }

    /**
     * Get a value by key
     * Time Complexity: O(1) average, O(n) worst case
     * @param {string} key - The key to lookup
     * @returns {*} - The value or undefined
     */
    get(key) {
        const index = this._hash(key);
        let node = this.buckets[index];

        while (node !== null) {
            if (node.key === key) {
                return node.value;
            }
            node = node.next;
        }

        return undefined;
    }

    /**
     * Check if a key exists
     * Time Complexity: O(1) average
     * @param {string} key - The key to check
     * @returns {boolean}
     */
    has(key) {
        return this.get(key) !== undefined;
    }

    /**
     * Remove a key-value pair
     * Time Complexity: O(1) average, O(n) worst case
     * @param {string} key - The key to remove
     * @returns {boolean} - True if removed
     */
    remove(key) {
        const index = this._hash(key);
        let node = this.buckets[index];
        let prev = null;

        while (node !== null) {
            if (node.key === key) {
                if (prev === null) {
                    this.buckets[index] = node.next;
                } else {
                    prev.next = node.next;
                }
                this.size--;
                return true;
            }
            prev = node;
            node = node.next;
        }

        return false;
    }

    /**
     * Get all keys
     * Time Complexity: O(n + m) where n = size, m = capacity
     * @returns {Array} - Array of keys
     */
    keys() {
        const keys = [];
        for (const bucket of this.buckets) {
            let node = bucket;
            while (node !== null) {
                keys.push(node.key);
                node = node.next;
            }
        }
        return keys;
    }

    /**
     * Get all values
     * Time Complexity: O(n + m)
     * @returns {Array} - Array of values
     */
    values() {
        const values = [];
        for (const bucket of this.buckets) {
            let node = bucket;
            while (node !== null) {
                values.push(node.value);
                node = node.next;
            }
        }
        return values;
    }

    /**
     * Get all entries as [key, value] pairs
     * Time Complexity: O(n + m)
     * @returns {Array} - Array of [key, value] pairs
     */
    entries() {
        const entries = [];
        for (const bucket of this.buckets) {
            let node = bucket;
            while (node !== null) {
                entries.push([node.key, node.value]);
                node = node.next;
            }
        }
        return entries;
    }

    /**
     * Clear all entries
     */
    clear() {
        this.buckets = new Array(this.capacity).fill(null);
        this.size = 0;
    }

    /**
     * Get the number of entries
     * @returns {number}
     */
    getSize() {
        return this.size;
    }

    /**
     * Check if empty
     * @returns {boolean}
     */
    isEmpty() {
        return this.size === 0;
    }

    /**
     * Resize the HashMap when load factor exceeded
     * Time Complexity: O(n)
     */
    _resize() {
        const oldBuckets = this.buckets;
        this.capacity *= 2;
        this.buckets = new Array(this.capacity).fill(null);
        this.size = 0;

        for (const bucket of oldBuckets) {
            let node = bucket;
            while (node !== null) {
                this.put(node.key, node.value);
                node = node.next;
            }
        }
    }

    /**
     * Iterate over entries with callback
     * @param {Function} callback - Function(value, key, map)
     */
    forEach(callback) {
        for (const [key, value] of this.entries()) {
            callback(value, key, this);
        }
    }

    /**
     * Get collision statistics (for debugging/analysis)
     * @returns {Object}
     */
    getStats() {
        let maxChainLength = 0;
        let totalChainLength = 0;
        let nonEmptyBuckets = 0;

        for (const bucket of this.buckets) {
            if (bucket !== null) {
                nonEmptyBuckets++;
                let chainLength = 0;
                let node = bucket;
                while (node !== null) {
                    chainLength++;
                    node = node.next;
                }
                totalChainLength += chainLength;
                maxChainLength = Math.max(maxChainLength, chainLength);
            }
        }

        return {
            size: this.size,
            capacity: this.capacity,
            loadFactor: this.size / this.capacity,
            nonEmptyBuckets,
            maxChainLength,
            avgChainLength: nonEmptyBuckets > 0 ? totalChainLength / nonEmptyBuckets : 0
        };
    }

    /**
     * Serialize HashMap for storage
     * @returns {string}
     */
    serialize() {
        return JSON.stringify(this.entries());
    }

    /**
     * Deserialize from storage
     * @param {string} jsonString
     * @returns {HashMap}
     */
    static deserialize(jsonString) {
        const map = new HashMap();
        try {
            const entries = JSON.parse(jsonString);
            for (const [key, value] of entries) {
                map.put(key, value);
            }
        } catch (e) {
            console.error('Failed to deserialize HashMap:', e);
        }
        return map;
    }
}
