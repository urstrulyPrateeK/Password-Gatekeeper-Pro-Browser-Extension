/**
 * Binary Search Utilities
 * Provides O(log n) search on sorted arrays
 * Used for searching password entries by various criteria
 */

export class BinarySearch {
    /**
     * Standard binary search for exact match
     * Time Complexity: O(log n)
     * @param {Array} arr - Sorted array
     * @param {*} target - Value to find
     * @param {Function} compareFn - Comparison function (optional)
     * @returns {number} - Index of target or -1
     */
    static search(arr, target, compareFn = null) {
        if (!arr || arr.length === 0) return -1;

        let left = 0;
        let right = arr.length - 1;

        while (left <= right) {
            const mid = Math.floor((left + right) / 2);
            const comparison = compareFn
                ? compareFn(arr[mid], target)
                : (arr[mid] < target ? -1 : arr[mid] > target ? 1 : 0);

            if (comparison === 0) {
                return mid;
            } else if (comparison < 0) {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }

        return -1;
    }

    /**
     * Find the first occurrence of target (for duplicates)
     * Time Complexity: O(log n)
     * @param {Array} arr - Sorted array
     * @param {*} target - Value to find
     * @param {Function} compareFn - Comparison function
     * @returns {number} - Index of first occurrence or -1
     */
    static searchFirst(arr, target, compareFn = null) {
        if (!arr || arr.length === 0) return -1;

        let left = 0;
        let right = arr.length - 1;
        let result = -1;

        while (left <= right) {
            const mid = Math.floor((left + right) / 2);
            const comparison = compareFn
                ? compareFn(arr[mid], target)
                : (arr[mid] < target ? -1 : arr[mid] > target ? 1 : 0);

            if (comparison === 0) {
                result = mid;
                right = mid - 1; // Continue searching left
            } else if (comparison < 0) {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }

        return result;
    }

    /**
     * Find the last occurrence of target (for duplicates)
     * Time Complexity: O(log n)
     * @param {Array} arr - Sorted array
     * @param {*} target - Value to find
     * @param {Function} compareFn - Comparison function
     * @returns {number} - Index of last occurrence or -1
     */
    static searchLast(arr, target, compareFn = null) {
        if (!arr || arr.length === 0) return -1;

        let left = 0;
        let right = arr.length - 1;
        let result = -1;

        while (left <= right) {
            const mid = Math.floor((left + right) / 2);
            const comparison = compareFn
                ? compareFn(arr[mid], target)
                : (arr[mid] < target ? -1 : arr[mid] > target ? 1 : 0);

            if (comparison === 0) {
                result = mid;
                left = mid + 1; // Continue searching right
            } else if (comparison < 0) {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }

        return result;
    }

    /**
     * Find insertion point (lower bound)
     * Returns index where target should be inserted to maintain order
     * Time Complexity: O(log n)
     * @param {Array} arr - Sorted array
     * @param {*} target - Value to find position for
     * @param {Function} compareFn - Comparison function
     * @returns {number} - Insertion index
     */
    static lowerBound(arr, target, compareFn = null) {
        if (!arr || arr.length === 0) return 0;

        let left = 0;
        let right = arr.length;

        while (left < right) {
            const mid = Math.floor((left + right) / 2);
            const comparison = compareFn
                ? compareFn(arr[mid], target)
                : (arr[mid] < target ? -1 : 1);

            if (comparison < 0) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        return left;
    }

    /**
     * Find upper bound
     * Returns index of first element greater than target
     * Time Complexity: O(log n)
     * @param {Array} arr - Sorted array
     * @param {*} target - Value to compare
     * @param {Function} compareFn - Comparison function
     * @returns {number} - Upper bound index
     */
    static upperBound(arr, target, compareFn = null) {
        if (!arr || arr.length === 0) return 0;

        let left = 0;
        let right = arr.length;

        while (left < right) {
            const mid = Math.floor((left + right) / 2);
            const comparison = compareFn
                ? compareFn(arr[mid], target)
                : (arr[mid] <= target ? -1 : 1);

            if (comparison <= 0) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        return left;
    }

    /**
     * Find elements in a range [low, high]
     * Time Complexity: O(log n + k) where k = number of elements in range
     * @param {Array} arr - Sorted array
     * @param {*} low - Lower bound (inclusive)
     * @param {*} high - Upper bound (inclusive)
     * @param {Function} compareFn - Comparison function
     * @returns {Array} - Elements in range
     */
    static searchRange(arr, low, high, compareFn = null) {
        if (!arr || arr.length === 0) return [];

        const startIdx = this.lowerBound(arr, low, compareFn);
        const endIdx = this.upperBound(arr, high, compareFn);

        return arr.slice(startIdx, endIdx);
    }

    /**
     * Find closest element to target
     * Time Complexity: O(log n)
     * @param {Array} arr - Sorted array
     * @param {*} target - Target value
     * @param {Function} valueFn - Function to extract numeric value
     * @returns {*} - Closest element
     */
    static findClosest(arr, target, valueFn = (x) => x) {
        if (!arr || arr.length === 0) return null;
        if (arr.length === 1) return arr[0];

        let left = 0;
        let right = arr.length - 1;

        while (right - left > 1) {
            const mid = Math.floor((left + right) / 2);
            if (valueFn(arr[mid]) <= target) {
                left = mid;
            } else {
                right = mid;
            }
        }

        const leftDiff = Math.abs(valueFn(arr[left]) - target);
        const rightDiff = Math.abs(valueFn(arr[right]) - target);

        return leftDiff <= rightDiff ? arr[left] : arr[right];
    }

    /**
     * Search password entries by date range
     * @param {Array} entries - Sorted password entries (by date)
     * @param {Date} startDate - Start date
     * @param {Date} endDate - End date
     * @returns {Array} - Entries within date range
     */
    static searchByDateRange(entries, startDate, endDate) {
        const compareFn = (entry, date) => {
            const entryTime = new Date(entry.createdAt || entry.updatedAt).getTime();
            const targetTime = date.getTime();
            return entryTime < targetTime ? -1 : entryTime > targetTime ? 1 : 0;
        };

        return this.searchRange(entries, startDate, endDate, compareFn);
    }

    /**
     * Search password entries by strength score range
     * @param {Array} entries - Sorted entries (by strength)
     * @param {number} minStrength - Minimum strength
     * @param {number} maxStrength - Maximum strength
     * @returns {Array} - Entries within strength range
     */
    static searchByStrengthRange(entries, minStrength, maxStrength) {
        const compareFn = (entry, strength) => {
            return entry.strength < strength ? -1 : entry.strength > strength ? 1 : 0;
        };

        return this.searchRange(entries, minStrength, maxStrength, compareFn);
    }
}
