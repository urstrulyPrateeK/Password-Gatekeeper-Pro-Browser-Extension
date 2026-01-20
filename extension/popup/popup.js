/**
 * Password Gatekeeper Pro - Popup Main Script
 * UI controller for the extension popup
 */

import { passwordManager } from '../js/classes/PasswordManager.js';
import { PasswordValidator } from '../js/classes/PasswordValidator.js';
import { PasswordGenerator } from '../js/classes/PasswordGenerator.js';
import { BreachChecker } from '../js/services/BreachChecker.js';

// ==========================================
// DOM Elements
// ==========================================

const elements = {
    // Screens
    lockScreen: document.getElementById('lockScreen'),
    mainScreen: document.getElementById('mainScreen'),

    // Lock screen
    loginForm: document.getElementById('loginForm'),
    registerForm: document.getElementById('registerForm'),
    masterPassword: document.getElementById('masterPassword'),
    newMasterPassword: document.getElementById('newMasterPassword'),
    confirmMasterPassword: document.getElementById('confirmMasterPassword'),
    unlockBtn: document.getElementById('unlockBtn'),
    createVaultBtn: document.getElementById('createVaultBtn'),
    showRegister: document.getElementById('showRegister'),
    showLogin: document.getElementById('showLogin'),
    passwordStrengthMeter: document.getElementById('passwordStrengthMeter'),

    // Header
    syncBtn: document.getElementById('syncBtn'),
    settingsBtn: document.getElementById('settingsBtn'),
    lockBtn: document.getElementById('lockBtn'),

    // Navigation
    navTabs: document.querySelectorAll('.nav-tab'),
    tabPanels: document.querySelectorAll('.tab-panel'),

    // Passwords tab
    searchPasswords: document.getElementById('searchPasswords'),
    passwordList: document.getElementById('passwordList'),
    addPasswordBtn: document.getElementById('addPasswordBtn'),

    // Generator tab
    generatedPassword: document.getElementById('generatedPassword'),
    copyPassword: document.getElementById('copyPassword'),
    regeneratePassword: document.getElementById('regeneratePassword'),
    generateBtn: document.getElementById('generateBtn'),
    passwordLength: document.getElementById('passwordLength'),
    lengthValue: document.getElementById('lengthValue'),
    includeUppercase: document.getElementById('includeUppercase'),
    includeLowercase: document.getElementById('includeLowercase'),
    includeNumbers: document.getElementById('includeNumbers'),
    includeSymbols: document.getElementById('includeSymbols'),
    generatorStrength: document.getElementById('generatorStrength'),

    // Security tab
    securityScore: document.getElementById('securityScore'),
    securityScoreCircle: document.getElementById('securityScoreCircle'),
    securityAlerts: document.getElementById('securityAlerts'),
    checkBreachesBtn: document.getElementById('checkBreachesBtn'),
    findDuplicatesBtn: document.getElementById('findDuplicatesBtn'),

    // Password modal
    passwordModal: document.getElementById('passwordModal'),
    modalTitle: document.getElementById('modalTitle'),
    passwordForm: document.getElementById('passwordForm'),
    entryWebsite: document.getElementById('entryWebsite'),
    entryUsername: document.getElementById('entryUsername'),
    entryPassword: document.getElementById('entryPassword'),
    entryNotes: document.getElementById('entryNotes'),
    entryTags: document.getElementById('entryTags'),
    entryId: document.getElementById('entryId'),
    entryStrengthBar: document.getElementById('entryStrengthBar'),
    generateForEntry: document.getElementById('generateForEntry'),

    // Settings modal
    settingsModal: document.getElementById('settingsModal'),
    apiUrl: document.getElementById('apiUrl'),
    syncEmail: document.getElementById('syncEmail'),
    syncPassword: document.getElementById('syncPassword'),
    testConnectionBtn: document.getElementById('testConnectionBtn'),
    autoLockTime: document.getElementById('autoLockTime'),
    clearClipboard: document.getElementById('clearClipboard'),
    exportBtn: document.getElementById('exportBtn'),
    importBtn: document.getElementById('importBtn'),
    importFile: document.getElementById('importFile'),
    resetVaultBtn: document.getElementById('resetVaultBtn'),

    // Toast
    toast: document.getElementById('toast')
};

// ==========================================
// State
// ==========================================

let currentEditId = null;
let searchDebounceTimer = null;

// ==========================================
// Initialization
// ==========================================

async function init() {
    setupEventListeners();

    const { exists, unlocked } = await passwordManager.initialize();

    if (unlocked) {
        showMainScreen();
        await loadPasswords();
        await updateSecurityScore();
    } else if (exists) {
        showLockScreen('login');
    } else {
        showLockScreen('register');
    }

    // Reset auto-lock timer
    chrome.runtime.sendMessage({ type: 'RESET_AUTO_LOCK' });
}

function setupEventListeners() {
    // Lock screen
    elements.showRegister.addEventListener('click', (e) => {
        e.preventDefault();
        showLockScreen('register');
    });

    elements.showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        showLockScreen('login');
    });

    elements.unlockBtn.addEventListener('click', handleUnlock);
    elements.createVaultBtn.addEventListener('click', handleCreateVault);

    elements.masterPassword.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleUnlock();
    });

    elements.newMasterPassword.addEventListener('input', () => {
        updateStrengthMeter(elements.newMasterPassword.value, elements.passwordStrengthMeter);
    });

    // Header actions
    elements.syncBtn.addEventListener('click', handleSync);
    elements.settingsBtn.addEventListener('click', () => openModal('settings'));
    elements.lockBtn.addEventListener('click', handleLock);

    // Navigation
    elements.navTabs.forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    // Passwords tab
    elements.searchPasswords.addEventListener('input', handleSearch);
    elements.addPasswordBtn.addEventListener('click', () => openPasswordModal());

    // Generator tab
    elements.generateBtn.addEventListener('click', generatePassword);
    elements.regeneratePassword.addEventListener('click', generatePassword);
    elements.copyPassword.addEventListener('click', () => copyToClipboard(elements.generatedPassword.value));
    elements.passwordLength.addEventListener('input', () => {
        elements.lengthValue.textContent = elements.passwordLength.value;
    });

    // Security tab
    elements.checkBreachesBtn.addEventListener('click', checkBreaches);
    elements.findDuplicatesBtn.addEventListener('click', findDuplicates);

    // Password modal
    elements.passwordForm.addEventListener('submit', handleSavePassword);
    elements.generateForEntry.addEventListener('click', generateForEntry);
    elements.entryPassword.addEventListener('input', () => {
        updateStrengthMeter(elements.entryPassword.value, elements.entryStrengthBar.parentElement);
    });

    // Settings modal
    elements.testConnectionBtn.addEventListener('click', testConnection);
    elements.exportBtn.addEventListener('click', handleExport);
    elements.importBtn.addEventListener('click', () => elements.importFile.click());
    elements.importFile.addEventListener('change', handleImport);
    elements.resetVaultBtn.addEventListener('click', handleReset);

    // Modal close buttons
    document.querySelectorAll('.close-modal, .cancel-btn').forEach(btn => {
        btn.addEventListener('click', closeModals);
    });

    // Password visibility toggles
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.target;
            const input = document.getElementById(targetId);
            input.type = input.type === 'password' ? 'text' : 'password';
        });
    });

    // Click outside modal to close
    [elements.passwordModal, elements.settingsModal].forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModals();
        });
    });

    // Listen for vault lock from background
    chrome.runtime.onMessage.addListener((request) => {
        if (request.type === 'VAULT_LOCKED') {
            handleLock();
        }
    });
}

// ==========================================
// Screen Management
// ==========================================

function showLockScreen(mode = 'login') {
    elements.lockScreen.classList.add('active');
    elements.mainScreen.classList.remove('active');

    if (mode === 'login') {
        elements.loginForm.classList.add('active');
        elements.registerForm.classList.remove('active');
        elements.masterPassword.focus();
    } else {
        elements.loginForm.classList.remove('active');
        elements.registerForm.classList.add('active');
        elements.newMasterPassword.focus();
    }
}

function showMainScreen() {
    elements.lockScreen.classList.remove('active');
    elements.mainScreen.classList.add('active');
}

function switchTab(tabName) {
    elements.navTabs.forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });

    elements.tabPanels.forEach(panel => {
        panel.classList.toggle('active', panel.id === `${tabName}Tab`);
    });

    // Load tab-specific data
    if (tabName === 'security') {
        updateSecurityScore();
    } else if (tabName === 'generator') {
        if (!elements.generatedPassword.value) {
            generatePassword();
        }
    }
}

// ==========================================
// Authentication Handlers
// ==========================================

async function handleUnlock() {
    const password = elements.masterPassword.value;
    if (!password) {
        showToast('Please enter your master password', 'error');
        return;
    }

    elements.unlockBtn.disabled = true;
    elements.unlockBtn.innerHTML = '<span class="spinner"></span>';

    try {
        const result = await passwordManager.unlockVault(password);

        if (result.success) {
            elements.masterPassword.value = '';
            showMainScreen();
            await loadPasswords();
            await updateSecurityScore();
            chrome.runtime.sendMessage({ type: 'VAULT_UNLOCKED' });
            showToast('Vault unlocked!', 'success');
        } else {
            showToast(result.message, 'error');
            elements.masterPassword.select();
        }
    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        elements.unlockBtn.disabled = false;
        elements.unlockBtn.innerHTML = '<span>Unlock Vault</span><svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
    }
}

async function handleCreateVault() {
    const password = elements.newMasterPassword.value;
    const confirm = elements.confirmMasterPassword.value;

    if (!password) {
        showToast('Please enter a master password', 'error');
        return;
    }

    if (password !== confirm) {
        showToast('Passwords do not match', 'error');
        return;
    }

    elements.createVaultBtn.disabled = true;
    elements.createVaultBtn.innerHTML = '<span class="spinner"></span>';

    try {
        const result = await passwordManager.createVault(password);

        if (result.success) {
            elements.newMasterPassword.value = '';
            elements.confirmMasterPassword.value = '';
            showMainScreen();
            chrome.runtime.sendMessage({ type: 'VAULT_UNLOCKED' });
            showToast('Vault created successfully!', 'success');
        } else {
            showToast(result.message, 'error');
        }
    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        elements.createVaultBtn.disabled = false;
        elements.createVaultBtn.innerHTML = '<span>Create Vault</span><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>';
    }
}

function handleLock() {
    passwordManager.lockVault();
    elements.passwordList.innerHTML = '';
    showLockScreen('login');
    chrome.runtime.sendMessage({ type: 'VAULT_LOCKED' });
}

// ==========================================
// Password List Management
// ==========================================

async function loadPasswords(query = '') {
    let entries;

    if (query) {
        entries = await passwordManager.searchPasswords(query);
    } else {
        entries = await passwordManager.getAllPasswords();
    }

    renderPasswordList(entries);
}

function renderPasswordList(entries) {
    if (entries.length === 0) {
        elements.passwordList.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="11" width="18" height="11" rx="2"/>
                    <path d="M7 11V7a5 5 0 0110 0v4"/>
                </svg>
                <h3>No passwords yet</h3>
                <p>Click the + button to add your first password</p>
            </div>
        `;
        return;
    }

    elements.passwordList.innerHTML = entries.map(entry => `
        <div class="password-entry" data-id="${entry.id}">
            <div class="entry-icon" style="background: ${getGradientForLetter(entry.getInitial())}">
                ${entry.getInitial()}
            </div>
            <div class="entry-details">
                <div class="entry-website">${escapeHtml(entry.extractDomain())}</div>
                <div class="entry-username">${escapeHtml(entry.username)}</div>
            </div>
            <div class="entry-actions">
                <button class="entry-action-btn copy-password" title="Copy Password">
                    <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                </button>
                <button class="entry-action-btn edit-entry" title="Edit">
                    <svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                </button>
                <button class="entry-action-btn delete-entry delete" title="Delete">
                    <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                </button>
            </div>
        </div>
    `).join('');

    // Add event listeners
    elements.passwordList.querySelectorAll('.password-entry').forEach(el => {
        const id = el.dataset.id;

        el.querySelector('.copy-password').addEventListener('click', (e) => {
            e.stopPropagation();
            copyPasswordById(id);
        });

        el.querySelector('.edit-entry').addEventListener('click', (e) => {
            e.stopPropagation();
            editPassword(id);
        });

        el.querySelector('.delete-entry').addEventListener('click', (e) => {
            e.stopPropagation();
            deletePassword(id);
        });

        // Click on entry to copy
        el.addEventListener('click', () => copyPasswordById(id));
    });
}

function handleSearch() {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
        loadPasswords(elements.searchPasswords.value);
    }, 300);
}

async function copyPasswordById(id) {
    const password = await passwordManager.getDecryptedPassword(id);
    if (password) {
        await copyToClipboard(password);
        showToast('Password copied!', 'success');
    }
}

async function editPassword(id) {
    const entries = await passwordManager.getAllPasswords();
    const entry = entries.find(e => e.id === id);

    if (entry) {
        currentEditId = id;
        elements.modalTitle.textContent = 'Edit Password';
        elements.entryWebsite.value = entry.website;
        elements.entryUsername.value = entry.username;
        elements.entryPassword.value = await passwordManager.getDecryptedPassword(id) || '';
        elements.entryNotes.value = entry.notes || '';
        elements.entryTags.value = (entry.tags || []).join(', ');
        elements.entryId.value = id;

        updateStrengthMeter(elements.entryPassword.value, elements.entryStrengthBar.parentElement);
        openModal('password');
    }
}

async function deletePassword(id) {
    if (!confirm('Are you sure you want to delete this password?')) {
        return;
    }

    const result = await passwordManager.deletePassword(id);
    if (result.success) {
        showToast('Password deleted', 'success');
        await loadPasswords(elements.searchPasswords.value);
        await updateSecurityScore();
    } else {
        showToast(result.message, 'error');
    }
}

// ==========================================
// Password Modal
// ==========================================

function openPasswordModal(website = '', username = '') {
    currentEditId = null;
    elements.modalTitle.textContent = 'Add Password';
    elements.passwordForm.reset();
    elements.entryWebsite.value = website;
    elements.entryUsername.value = username;
    elements.entryId.value = '';
    openModal('password');
    elements.entryWebsite.focus();
}

async function handleSavePassword(e) {
    e.preventDefault();

    const data = {
        website: elements.entryWebsite.value,
        username: elements.entryUsername.value,
        password: elements.entryPassword.value,
        notes: elements.entryNotes.value,
        tags: elements.entryTags.value.split(',').map(t => t.trim()).filter(Boolean)
    };

    let result;

    if (currentEditId) {
        result = await passwordManager.updatePassword(currentEditId, {
            ...data,
            password: data.password
        });
    } else {
        result = await passwordManager.addPassword(data);
    }

    if (result.success) {
        closeModals();
        await loadPasswords(elements.searchPasswords.value);
        await updateSecurityScore();
        showToast(currentEditId ? 'Password updated!' : 'Password saved!', 'success');
    } else {
        showToast(result.message, 'error');
    }
}

function generateForEntry() {
    const password = PasswordGenerator.generate({
        length: 16,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true
    });

    elements.entryPassword.value = password;
    elements.entryPassword.type = 'text';
    updateStrengthMeter(password, elements.entryStrengthBar.parentElement);
}

// ==========================================
// Password Generator
// ==========================================

function generatePassword() {
    const result = passwordManager.generatePassword({
        length: parseInt(elements.passwordLength.value),
        includeUppercase: elements.includeUppercase.checked,
        includeLowercase: elements.includeLowercase.checked,
        includeNumbers: elements.includeNumbers.checked,
        includeSymbols: elements.includeSymbols.checked
    });

    elements.generatedPassword.value = result.password;
    updateGeneratorStrength(result.strength);
}

function updateGeneratorStrength(validation) {
    const segments = elements.generatorStrength.querySelector('.strength-segments');
    const label = elements.generatorStrength.querySelector('.strength-label');

    segments.className = 'strength-segments';

    if (validation.score >= 80) {
        segments.classList.add('strong');
        label.textContent = 'Strong';
    } else if (validation.score >= 60) {
        segments.classList.add('good');
        label.textContent = 'Good';
    } else if (validation.score >= 40) {
        segments.classList.add('fair');
        label.textContent = 'Fair';
    } else {
        segments.classList.add('weak');
        label.textContent = 'Weak';
    }
}

// ==========================================
// Security Analysis
// ==========================================

async function updateSecurityScore() {
    try {
        const analysis = await passwordManager.analyzeSecurityScore();

        // Update score display
        elements.securityScore.textContent = analysis.score;

        // Animate score circle
        const circumference = 2 * Math.PI * 45;
        const offset = circumference - (analysis.score / 100) * circumference;
        elements.securityScoreCircle.style.strokeDashoffset = offset;

        // Update color based on score
        const color = analysis.score >= 80 ? '#22c55e' :
            analysis.score >= 60 ? '#84cc16' :
                analysis.score >= 40 ? '#f59e0b' : '#ef4444';
        elements.securityScoreCircle.style.stroke = color;

        // Render alerts
        renderSecurityAlerts(analysis.issues);
    } catch (error) {
        console.error('Security analysis failed:', error);
    }
}

function renderSecurityAlerts(issues) {
    if (issues.length === 0) {
        elements.securityAlerts.innerHTML = `
            <div class="alert-item success">
                <div class="alert-icon">
                    <svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                </div>
                <div class="alert-content">
                    <div class="alert-title">All Good!</div>
                    <div class="alert-description">No security issues detected</div>
                </div>
            </div>
        `;
        return;
    }

    elements.securityAlerts.innerHTML = issues.map(issue => `
        <div class="alert-item ${issue.severity === 'high' ? '' : 'warning'}">
            <div class="alert-icon">
                <svg viewBox="0 0 24 24"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            </div>
            <div class="alert-content">
                <div class="alert-title">${escapeHtml(issue.message)}</div>
                <div class="alert-description">${getIssueDescription(issue.type)}</div>
            </div>
        </div>
    `).join('');
}

function getIssueDescription(type) {
    const descriptions = {
        'weak': 'Consider updating these passwords to stronger ones',
        'old': 'Regularly changing passwords improves security',
        'reused': 'Using unique passwords for each account is recommended',
        'low-variance': 'Try using more diverse password patterns'
    };
    return descriptions[type] || '';
}

async function checkBreaches() {
    showToast('Checking for breaches...', 'info');

    const entries = await passwordManager.getAllPasswords();
    const passwords = await Promise.all(
        entries.map(async e => ({
            id: e.id,
            website: e.website,
            password: await passwordManager.getDecryptedPassword(e.id)
        }))
    );

    const analysis = await BreachChecker.analyzeVault(passwords);

    if (analysis.breachedCount > 0) {
        showToast(`Found ${analysis.breachedCount} breached password(s)!`, 'error');
    } else {
        showToast('No breached passwords found!', 'success');
    }

    await updateSecurityScore();
}

async function findDuplicates() {
    const duplicates = await passwordManager.findDuplicates();

    if (duplicates.length > 0) {
        showToast(`Found ${duplicates.length} group(s) of similar passwords`, 'warning');
    } else {
        showToast('No duplicate passwords found!', 'success');
    }
}

// ==========================================
// Sync & Settings
// ==========================================

async function handleSync() {
    elements.syncBtn.classList.add('spinning');
    showToast('Syncing...', 'info');

    try {
        const result = await passwordManager.sync();
        if (result.success) {
            showToast('Sync completed!', 'success');
            await loadPasswords();
        } else {
            showToast(result.message, 'error');
        }
    } catch (error) {
        showToast('Sync failed: ' + error.message, 'error');
    } finally {
        elements.syncBtn.classList.remove('spinning');
    }
}

async function testConnection() {
    const url = elements.apiUrl.value;
    if (!url) {
        showToast('Please enter API URL', 'error');
        return;
    }

    passwordManager.configureSync({ apiUrl: url });
    showToast('Testing connection...', 'info');
    // Connection test would be implemented here
}

async function handleExport() {
    try {
        const data = await passwordManager.exportVault();
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `password-gatekeeper-export-${Date.now()}.json`;
        a.click();

        URL.revokeObjectURL(url);
        showToast('Export successful!', 'success');
    } catch (error) {
        showToast('Export failed: ' + error.message, 'error');
    }
}

async function handleImport() {
    const file = elements.importFile.files[0];
    if (!file) return;

    try {
        const data = await file.text();
        const result = await passwordManager.importVault(data, true);

        if (result.success) {
            showToast(`Imported ${result.imported} password(s)!`, 'success');
            await loadPasswords();
            await updateSecurityScore();
        } else {
            showToast('Import failed: ' + result.errors.join(', '), 'error');
        }
    } catch (error) {
        showToast('Import failed: ' + error.message, 'error');
    }

    elements.importFile.value = '';
}

async function handleReset() {
    if (!confirm('Are you sure you want to reset the vault? This will delete ALL passwords!')) {
        return;
    }

    if (!confirm('This action cannot be undone. Type "RESET" to confirm.')) {
        return;
    }

    const confirmation = prompt('Type RESET to confirm:');
    if (confirmation !== 'RESET') {
        showToast('Reset cancelled', 'info');
        return;
    }

    try {
        await chrome.storage.local.clear();
        closeModals();
        showLockScreen('register');
        showToast('Vault reset successfully', 'success');
    } catch (error) {
        showToast('Reset failed: ' + error.message, 'error');
    }
}

// ==========================================
// Modal Management
// ==========================================

function openModal(type) {
    closeModals();

    if (type === 'password') {
        elements.passwordModal.classList.add('active');
    } else if (type === 'settings') {
        elements.settingsModal.classList.add('active');
    }
}

function closeModals() {
    elements.passwordModal.classList.remove('active');
    elements.settingsModal.classList.remove('active');
    currentEditId = null;
}

// ==========================================
// Utility Functions
// ==========================================

function updateStrengthMeter(password, container) {
    if (!container) return;

    const bar = container.querySelector('.strength-bar');
    const text = container.querySelector('.strength-text');

    if (!password || password.length === 0) {
        bar.style.setProperty('--strength', '0%');
        bar.style.setProperty('--strength-color', '#6b7280');
        if (text) text.textContent = '';
        return;
    }

    const validation = PasswordValidator.validate(password);
    const color = PasswordValidator.getStrengthColor(validation.strength);

    bar.style.setProperty('--strength', `${validation.score}%`);
    bar.style.setProperty('--strength-color', color);
    if (text) text.textContent = validation.label;
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        chrome.runtime.sendMessage({ type: 'COPY_TO_CLIPBOARD', text });
    } catch (error) {
        // Fallback
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    }
}

function showToast(message, type = 'info') {
    elements.toast.querySelector('.toast-message').textContent = message;
    elements.toast.className = `toast ${type} show`;

    setTimeout(() => {
        elements.toast.classList.remove('show');
    }, 3000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getGradientForLetter(letter) {
    const gradients = [
        'linear-gradient(135deg, #6366f1, #a855f7)',
        'linear-gradient(135deg, #3b82f6, #06b6d4)',
        'linear-gradient(135deg, #22c55e, #14b8a6)',
        'linear-gradient(135deg, #f59e0b, #ef4444)',
        'linear-gradient(135deg, #ec4899, #8b5cf6)',
        'linear-gradient(135deg, #f97316, #eab308)'
    ];

    const index = (letter.charCodeAt(0) % gradients.length);
    return gradients[index];
}

// ==========================================
// Initialize
// ==========================================

document.addEventListener('DOMContentLoaded', init);
