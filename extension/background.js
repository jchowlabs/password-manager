// Background Service Worker for Password Manager Extension

// Listen for extension installation
chrome.runtime.onInstalled.addListener(() => {
    console.log('Password Manager Extension installed');
});

// Handle messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'savePassword') {
        handleSavePassword(request.data)
            .then(response => sendResponse({ success: true, data: response }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true; // Keep channel open for async response
    }
    
    if (request.action === 'getPassword') {
        handleGetPassword(request.website)
            .then(response => sendResponse({ success: true, data: response }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
    }
});

// Helper function to save password
async function handleSavePassword(data) {
    const { authToken } = await chrome.storage.local.get(['authToken']);
    
    if (!authToken) {
        throw new Error('Not authenticated');
    }

    const response = await fetch('http://localhost:8000/api/vault/save', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify(data)
    });

    if (!response.ok) {
        throw new Error('Failed to save password');
    }

    return await response.json();
}

// Helper function to get password for a website
async function handleGetPassword(website) {
    const { authToken } = await chrome.storage.local.get(['authToken']);
    
    if (!authToken) {
        throw new Error('Not authenticated');
    }

    const response = await fetch('http://localhost:8000/api/vault/list', {
        headers: {
            'Authorization': `Bearer ${authToken}`
        }
    });

    if (!response.ok) {
        throw new Error('Failed to retrieve passwords');
    }

    const data = await response.json();
    return data.passwords.filter(p => p.website === website);
}
