/**
 * Password Gatekeeper Pro - Service Worker
 * Background script for the extension
 * Handles alarms, clipboard clearing, and message passing
 */

// Auto-lock alarm name
const AUTO_LOCK_ALARM = 'autoLockVault';
const CLIPBOARD_CLEAR_ALARM = 'clearClipboard';

// Extension state
let isVaultUnlocked = false;
let settings = {
    autoLockTime: 5,
    clearClipboard: true,
    clipboardTimeout: 30
};

// Initialize on install
chrome.runtime.onInstalled.addListener(async (details) => {
    console.log('Password Gatekeeper Pro installed:', details.reason);

    // Set default settings
    const stored = await chrome.storage.local.get('settings');
    if (!stored.settings) {
        await chrome.storage.local.set({ settings });
    } else {
        settings = stored.settings;
    }
});

// Handle alarms
chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === AUTO_LOCK_ALARM) {
        console.log('Auto-locking vault');
        isVaultUnlocked = false;

        // Notify popup if open
        chrome.runtime.sendMessage({ type: 'VAULT_LOCKED' }).catch(() => {
            // Popup not open, ignore
        });
    }

    if (alarm.name === CLIPBOARD_CLEAR_ALARM) {
        console.log('Clearing clipboard');
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab?.id) {
                await chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    func: () => navigator.clipboard.writeText('')
                });
            }
        } catch (e) {
            console.log('Could not clear clipboard:', e);
        }
    }
});

// Message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    handleMessage(request, sender, sendResponse);
    return true; // Keep channel open for async response
});

async function handleMessage(request, sender, sendResponse) {
    try {
        switch (request.type) {
            case 'VAULT_UNLOCKED':
                isVaultUnlocked = true;
                scheduleAutoLock();
                sendResponse({ success: true });
                break;

            case 'VAULT_LOCKED':
                isVaultUnlocked = false;
                chrome.alarms.clear(AUTO_LOCK_ALARM);
                sendResponse({ success: true });
                break;

            case 'RESET_AUTO_LOCK':
                scheduleAutoLock();
                sendResponse({ success: true });
                break;

            case 'COPY_TO_CLIPBOARD':
                await copyToClipboard(request.text);
                sendResponse({ success: true });
                break;

            case 'GET_CURRENT_URL':
                const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
                sendResponse({ url: tabs[0]?.url || '' });
                break;

            case 'FILL_CREDENTIALS':
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (tab?.id) {
                    chrome.tabs.sendMessage(tab.id, {
                        type: 'FILL_CREDENTIALS',
                        username: request.username,
                        password: request.password
                    });
                }
                sendResponse({ success: true });
                break;

            case 'UPDATE_SETTINGS':
                settings = { ...settings, ...request.settings };
                await chrome.storage.local.set({ settings });
                sendResponse({ success: true });
                break;

            case 'GET_SETTINGS':
                const stored = await chrome.storage.local.get('settings');
                sendResponse({ settings: stored.settings || settings });
                break;

            default:
                sendResponse({ error: 'Unknown message type' });
        }
    } catch (error) {
        console.error('Message handler error:', error);
        sendResponse({ error: error.message });
    }
}

// Schedule auto-lock alarm
function scheduleAutoLock() {
    chrome.alarms.clear(AUTO_LOCK_ALARM);

    if (settings.autoLockTime > 0) {
        chrome.alarms.create(AUTO_LOCK_ALARM, {
            delayInMinutes: settings.autoLockTime
        });
    }
}

// Copy to clipboard with auto-clear
async function copyToClipboard(text) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tab?.id) {
        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: (textToCopy) => navigator.clipboard.writeText(textToCopy),
            args: [text]
        });
    }

    if (settings.clearClipboard) {
        chrome.alarms.clear(CLIPBOARD_CLEAR_ALARM);
        chrome.alarms.create(CLIPBOARD_CLEAR_ALARM, {
            delayInMinutes: settings.clipboardTimeout / 60
        });
    }
}

console.log('Password Gatekeeper Pro service worker started');
