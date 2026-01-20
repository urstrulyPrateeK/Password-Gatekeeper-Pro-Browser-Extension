/**
 * Sorting Algorithms Implementation
 * Provides various sorting algorithms for password entries
 * Includes QuickSort, MergeSort with custom comparators
 */

export class SortingAlgorithms {
    /**
     * QuickSort implementation
     * Time Complexity: O(n log n) average, O(n²) worst case
     * Space Complexity: O(log n)
     * @param {Array} arr - Array to sort
     * @param {Function} compareFn - Comparison function
     * @returns {Array} - Sorted array (in-place)
     */
    static quickSort(arr, compareFn = (a, b) => a - b) {
        if (!arr || arr.length <= 1) return arr;

        this._quickSortHelper(arr, 0, arr.length - 1, compareFn);
        return arr;
    }

    static _quickSortHelper(arr, low, high, compareFn) {
        if (low < high) {
            const pivotIndex = this._partition(arr, low, high, compareFn);
            this._quickSortHelper(arr, low, pivotIndex - 1, compareFn);
            this._quickSortHelper(arr, pivotIndex + 1, high, compareFn);
        }
    }

    static _partition(arr, low, high, compareFn) {
        // Use median-of-three pivot selection for better performance
        const mid = Math.floor((low + high) / 2);
        if (compareFn(arr[low], arr[mid]) > 0) this._swap(arr, low, mid);
        if (compareFn(arr[low], arr[high]) > 0) this._swap(arr, low, high);
        if (compareFn(arr[mid], arr[high]) > 0) this._swap(arr, mid, high);

        this._swap(arr, mid, high - 1);
        const pivot = arr[high - 1];

        let i = low;
        let j = high - 1;

        while (true) {
            while (compareFn(arr[++i], pivot) < 0) { }
            while (j > low && compareFn(arr[--j], pivot) > 0) { }

            if (i >= j) break;
            this._swap(arr, i, j);
        }

        this._swap(arr, i, high - 1);
        return i;
    }

    /**
     * MergeSort implementation (stable sort)
     * Time Complexity: O(n log n)
     * Space Complexity: O(n)
     * @param {Array} arr - Array to sort
     * @param {Function} compareFn - Comparison function
     * @returns {Array} - New sorted array
     */
    static mergeSort(arr, compareFn = (a, b) => a - b) {
        if (!arr || arr.length <= 1) return arr.slice();

        return this._mergeSortHelper(arr.slice(), compareFn);
    }

    static _mergeSortHelper(arr, compareFn) {
        if (arr.length <= 1) return arr;

        const mid = Math.floor(arr.length / 2);
        const left = this._mergeSortHelper(arr.slice(0, mid), compareFn);
        const right = this._mergeSortHelper(arr.slice(mid), compareFn);

        return this._merge(left, right, compareFn);
    }

    static _merge(left, right, compareFn) {
        const result = [];
        let i = 0, j = 0;

        while (i < left.length && j < right.length) {
            if (compareFn(left[i], right[j]) <= 0) {
                result.push(left[i++]);
            } else {
                result.push(right[j++]);
            }
        }

        return result.concat(left.slice(i)).concat(right.slice(j));
    }

    /**
     * HeapSort implementation
     * Time Complexity: O(n log n)
     * Space Complexity: O(1)
     * @param {Array} arr - Array to sort
     * @param {Function} compareFn - Comparison function
     * @returns {Array} - Sorted array (in-place)
     */
    static heapSort(arr, compareFn = (a, b) => a - b) {
        if (!arr || arr.length <= 1) return arr;

        const n = arr.length;

        // Build max heap
        for (let i = Math.floor(n / 2) - 1; i >= 0; i--) {
            this._heapify(arr, n, i, compareFn);
        }

        // Extract elements from heap
        for (let i = n - 1; i > 0; i--) {
            this._swap(arr, 0, i);
            this._heapify(arr, i, 0, compareFn);
        }

        return arr;
    }

    static _heapify(arr, n, i, compareFn) {
        let largest = i;
        const left = 2 * i + 1;
        const right = 2 * i + 2;

        if (left < n && compareFn(arr[left], arr[largest]) > 0) {
            largest = left;
        }

        if (right < n && compareFn(arr[right], arr[largest]) > 0) {
            largest = right;
        }

        if (largest !== i) {
            this._swap(arr, i, largest);
            this._heapify(arr, n, largest, compareFn);
        }
    }

    static _swap(arr, i, j) {
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }

    // ==========================================
    // Custom Comparators for Password Entries
    // ==========================================

    /**
     * Compare by website name (alphabetically)
     */
    static compareByWebsite(a, b) {
        const websiteA = (a.website || '').toLowerCase();
        const websiteB = (b.website || '').toLowerCase();
        return websiteA.localeCompare(websiteB);
    }

    /**
     * Compare by username (alphabetically)
     */
    static compareByUsername(a, b) {
        const usernameA = (a.username || '').toLowerCase();
        const usernameB = (b.username || '').toLowerCase();
        return usernameA.localeCompare(usernameB);
    }

    /**
     * Compare by creation date (newest first)
     */
    static compareByDateDesc(a, b) {
        const dateA = new Date(a.createdAt || 0).getTime();
        const dateB = new Date(b.createdAt || 0).getTime();
        return dateB - dateA;
    }

    /**
     * Compare by creation date (oldest first)
     */
    static compareByDateAsc(a, b) {
        const dateA = new Date(a.createdAt || 0).getTime();
        const dateB = new Date(b.createdAt || 0).getTime();
        return dateA - dateB;
    }

    /**
     * Compare by last updated (most recent first)
     */
    static compareByUpdatedDesc(a, b) {
        const dateA = new Date(a.updatedAt || a.createdAt || 0).getTime();
        const dateB = new Date(b.updatedAt || b.createdAt || 0).getTime();
        return dateB - dateA;
    }

    /**
     * Compare by password strength (weakest first)
     */
    static compareByStrengthAsc(a, b) {
        return (a.strength || 0) - (b.strength || 0);
    }

    /**
     * Compare by password strength (strongest first)
     */
    static compareByStrengthDesc(a, b) {
        return (b.strength || 0) - (a.strength || 0);
    }

    /**
     * Sort password entries by specified criteria
     * @param {Array} entries - Password entries to sort
     * @param {string} sortBy - Sorting criteria: 'website', 'username', 'dateAsc', 'dateDesc', 'strengthAsc', 'strengthDesc'
     * @param {boolean} stable - Use stable sort (MergeSort) or not (QuickSort)
     * @returns {Array} - Sorted entries
     */
    static sortEntries(entries, sortBy = 'website', stable = true) {
        const comparators = {
            'website': this.compareByWebsite,
            'username': this.compareByUsername,
            'dateAsc': this.compareByDateAsc,
            'dateDesc': this.compareByDateDesc,
            'updatedDesc': this.compareByUpdatedDesc,
            'strengthAsc': this.compareByStrengthAsc,
            'strengthDesc': this.compareByStrengthDesc
        };

        const compareFn = comparators[sortBy] || this.compareByWebsite;

        if (stable) {
            return this.mergeSort(entries, compareFn);
        } else {
            return this.quickSort([...entries], compareFn);
        }
    }

    /**
     * Multi-key sort (sort by primary, then secondary criteria)
     * @param {Array} entries - Password entries
     * @param {Array} sortKeys - Array of sort criteria in order of priority
     * @returns {Array} - Sorted entries
     */
    static multiKeySort(entries, sortKeys) {
        const comparators = {
            'website': this.compareByWebsite,
            'username': this.compareByUsername,
            'dateAsc': this.compareByDateAsc,
            'dateDesc': this.compareByDateDesc,
            'strengthAsc': this.compareByStrengthAsc,
            'strengthDesc': this.compareByStrengthDesc
        };

        const multiComparator = (a, b) => {
            for (const key of sortKeys) {
                const compareFn = comparators[key];
                if (compareFn) {
                    const result = compareFn(a, b);
                    if (result !== 0) return result;
                }
            }
            return 0;
        };

        return this.mergeSort(entries, multiComparator);
    }
}
