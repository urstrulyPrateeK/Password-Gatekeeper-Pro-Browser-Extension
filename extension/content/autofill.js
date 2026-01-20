/**
 * Password Gatekeeper Pro - Autofill Content Script
 * Detects login forms and fills credentials
 */

(function () {
    'use strict';

    // Form detection patterns
    const LOGIN_SELECTORS = {
        username: [
            'input[type="email"]',
            'input[type="text"][name*="user"]',
            'input[type="text"][name*="email"]',
            'input[type="text"][name*="login"]',
            'input[type="text"][id*="user"]',
            'input[type="text"][id*="email"]',
            'input[type="text"][id*="login"]',
            'input[autocomplete="username"]',
            'input[autocomplete="email"]'
        ],
        password: [
            'input[type="password"]',
            'input[autocomplete="current-password"]',
            'input[autocomplete="new-password"]'
        ]
    };

    // Icon SVG for autofill button
    const ICON_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2"/>
        <path d="M7 11V7a5 5 0 0110 0v4"/>
    </svg>`;

    // Detected forms cache
    const detectedForms = new Map();

    // Initialize
    function init() {
        detectLoginForms();

        // Watch for dynamic forms
        const observer = new MutationObserver(debounce(detectLoginForms, 500));
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    // Detect login forms on page
    function detectLoginForms() {
        const passwordFields = document.querySelectorAll(LOGIN_SELECTORS.password.join(', '));

        passwordFields.forEach(passwordField => {
            if (detectedForms.has(passwordField)) return;

            // Find associated username field
            const form = passwordField.closest('form');
            let usernameField = null;

            if (form) {
                usernameField = form.querySelector(LOGIN_SELECTORS.username.join(', '));
            } else {
                // Look for nearby username field
                const container = passwordField.closest('div, section, main') || document.body;
                usernameField = container.querySelector(LOGIN_SELECTORS.username.join(', '));
            }

            // Add autofill button
            addAutofillButton(passwordField, usernameField);
            detectedForms.set(passwordField, { usernameField });
        });
    }

    // Add autofill button to password field
    function addAutofillButton(passwordField, usernameField) {
        // Check if button already exists
        if (passwordField.parentElement.querySelector('.pg-autofill-btn')) return;

        // Create wrapper if needed
        let wrapper = passwordField.parentElement;
        if (!wrapper.classList.contains('pg-field-wrapper')) {
            wrapper = document.createElement('div');
            wrapper.classList.add('pg-field-wrapper');
            passwordField.parentElement.insertBefore(wrapper, passwordField);
            wrapper.appendChild(passwordField);
        }

        // Create autofill button
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'pg-autofill-btn';
        btn.innerHTML = ICON_SVG;
        btn.title = 'Fill with Password Gatekeeper';

        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            requestAutofill(passwordField, usernameField);
        });

        wrapper.appendChild(btn);
    }

    // Request autofill from extension
    async function requestAutofill(passwordField, usernameField) {
        try {
            // Get current page URL
            const currentUrl = window.location.href;

            // Send message to background script
            chrome.runtime.sendMessage({
                type: 'REQUEST_AUTOFILL',
                url: currentUrl
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.log('Extension not available');
                    return;
                }

                if (response && response.username && response.password) {
                    fillCredentials(usernameField, passwordField, response.username, response.password);
                }
            });
        } catch (error) {
            console.error('Autofill request failed:', error);
        }
    }

    // Fill credentials into fields
    function fillCredentials(usernameField, passwordField, username, password) {
        if (usernameField && username) {
            setFieldValue(usernameField, username);
        }

        if (passwordField && password) {
            setFieldValue(passwordField, password);
        }

        // Show success animation
        showFillSuccess(passwordField);
    }

    // Set field value with proper event triggering
    function setFieldValue(field, value) {
        // Focus the field
        field.focus();

        // Clear existing value
        field.value = '';

        // Set new value
        field.value = value;

        // Trigger input events for frameworks like React/Vue
        const inputEvent = new Event('input', { bubbles: true, cancelable: true });
        field.dispatchEvent(inputEvent);

        const changeEvent = new Event('change', { bubbles: true, cancelable: true });
        field.dispatchEvent(changeEvent);

        // Blur to trigger validation
        field.blur();
    }

    // Show success animation
    function showFillSuccess(field) {
        const btn = field.parentElement.querySelector('.pg-autofill-btn');
        if (btn) {
            btn.classList.add('pg-fill-success');
            setTimeout(() => btn.classList.remove('pg-fill-success'), 1000);
        }
    }

    // Listen for messages from extension
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.type === 'FILL_CREDENTIALS') {
            // Find password field and fill
            const passwordField = document.querySelector(LOGIN_SELECTORS.password.join(', '));
            if (passwordField) {
                const formData = detectedForms.get(passwordField);
                fillCredentials(formData?.usernameField, passwordField, request.username, request.password);
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false, error: 'No password field found' });
            }
        }

        if (request.type === 'FILL_PASSWORD') {
            // Fill generated password
            const activeElement = document.activeElement;
            if (activeElement && activeElement.type === 'password') {
                setFieldValue(activeElement, request.password);
                sendResponse({ success: true });
            }
        }

        if (request.type === 'GET_LOGIN_FORMS') {
            // Return detected forms for popup
            const forms = [];
            detectedForms.forEach((data, passwordField) => {
                forms.push({
                    hasUsername: !!data.usernameField,
                    formAction: passwordField.closest('form')?.action || window.location.href
                });
            });
            sendResponse({ forms });
        }

        return true;
    });

    // Debounce utility
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
