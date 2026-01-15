// Background Service Worker for Password Manager Extension

const API_BASE_URL = 'http://localhost:8000';

// In-memory vault cache
let vaultCache = null;
let vaultCacheTimestamp = null;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// JWT Helper Functions
function decodeJWT(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => 
            '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
        ).join(''));
        return JSON.parse(jsonPayload);
    } catch (e) {
        return null;
    }
}

function isTokenExpired(token) {
    if (!token) return true;
    
    const payload = decodeJWT(token);
    if (!payload || !payload.exp) return true;
    
    // Check if token expires in next 60 seconds
    return (payload.exp * 1000) < (Date.now() + 60000);
}

async function checkAuthToken() {
    const { authToken } = await chrome.storage.local.get(['authToken']);
    
    if (!authToken) {
        throw new Error('NOT_AUTHENTICATED');
    }
    
    if (isTokenExpired(authToken)) {
        // Clear expired token
        await chrome.storage.local.remove(['authToken', 'userEmail', 'encryptionKey']);
        vaultCache = null;
        throw new Error('TOKEN_EXPIRED');
    }
    
    return authToken;
}

// API Handler Functions
async function apiRequest(endpoint, options = {}) {
    const authToken = await checkAuthToken();
    
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
        }
    };
    
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...defaultOptions,
        ...options,
        headers: { ...defaultOptions.headers, ...options.headers }
    });
    
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.detail || `API Error: ${response.status}`);
    }
    
    return await response.json();
}

// Message Handlers
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    const handlers = {
        // Authentication endpoints (no auth token required)
        'auth:login': () => handleLogin(request.data),
        'auth:verifyLogin': () => handleVerifyLogin(request.data),
        'auth:signup': () => handleSignup(request.data),
        'auth:verifyEmail': () => handleVerifyEmail(request.data),
        'auth:resendVerification': () => handleResendVerification(request.data),
        'auth:forgotPassword': () => handleForgotPassword(request.data),
        'auth:resetPassword': () => handleResetPassword(request.data),
        
        // Vault operations (require auth token)
        'vault:list': () => handleVaultList(),
        'vault:save': () => handleVaultSave(request.data),
        'vault:delete': () => handleVaultDelete(request.data),
        
        // Password generation (require auth token)
        'password:generate': () => handleGeneratePassword(request.data)
    };
    
    const handler = handlers[request.action];
    if (handler) {
        handler()
            .then(response => sendResponse({ success: true, data: response }))
            .catch(error => sendResponse({ 
                success: false, 
                error: error.message,
                isAuthError: error.message === 'TOKEN_EXPIRED' || error.message === 'NOT_AUTHENTICATED'
            }));
        return true; // Keep channel open for async response
    }
    
    sendResponse({ success: false, error: 'Unknown action' });
});

// Authentication Handlers (no token needed)
async function handleLogin(data) {
    const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Login failed');
    }
    
    return await response.json();
}

async function handleVerifyLogin(data) {
    const response = await fetch(`${API_BASE_URL}/api/auth/verify-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Verification failed');
    }
    
    return await response.json();
}

async function handleSignup(data) {
    const response = await fetch(`${API_BASE_URL}/api/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    
    const result = await response.json();
    
    if (!response.ok) {
        throw new Error(result.detail || 'Signup failed');
    }
    
    return result;
}

async function handleVerifyEmail(data) {
    const response = await fetch(`${API_BASE_URL}/api/auth/verify-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    
    const result = await response.json();
    
    if (!response.ok) {
        throw new Error(result.detail || 'Verification failed');
    }
    
    return result;
}

async function handleResendVerification(data) {
    const response = await fetch(`${API_BASE_URL}/api/auth/resend-verification`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    
    const result = await response.json();
    
    if (!response.ok) {
        throw new Error(result.detail || 'Failed to resend code');
    }
    
    return result;
}

async function handleForgotPassword(data) {
    const response = await fetch(`${API_BASE_URL}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to send reset code');
    }
    
    return await response.json();
}

async function handleResetPassword(data) {
    const response = await fetch(`${API_BASE_URL}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to reset password');
    }
    
    return await response.json();
}

// Vault Handlers (require auth token + caching)
async function handleVaultList() {
    // Check cache first
    if (vaultCache && vaultCacheTimestamp && (Date.now() - vaultCacheTimestamp < CACHE_DURATION)) {
        return { passwords: vaultCache, fromCache: true };
    }
    
    // Fetch from API
    const data = await apiRequest('/api/vault/list');
    
    // Update cache
    vaultCache = data.passwords;
    vaultCacheTimestamp = Date.now();
    
    return data;
}

async function handleVaultSave(data) {
    const result = await apiRequest('/api/vault/save', {
        method: 'POST',
        body: JSON.stringify(data)
    });
    
    // Invalidate cache
    vaultCache = null;
    vaultCacheTimestamp = null;
    
    return result;
}

async function handleVaultDelete(data) {
    await apiRequest(`/api/vault/${data.passwordId}`, {
        method: 'DELETE'
    });
    
    // Invalidate cache
    vaultCache = null;
    vaultCacheTimestamp = null;
    
    return { message: 'Password deleted successfully' };
}

// Password Generation Handler
async function handleGeneratePassword(data) {
    return await apiRequest('/api/passwords/generate', {
        method: 'POST',
        body: JSON.stringify(data)
    });
}

// Listen for extension installation
chrome.runtime.onInstalled.addListener(() => {
    console.log('Password Manager Extension installed');
});
