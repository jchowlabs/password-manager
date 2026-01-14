// API Configuration
const API_BASE_URL = 'http://localhost:8000';

// Crypto Configuration
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;

// Crypto Utilities
class CryptoManager {
    static async deriveKey(password, salt) {
        /**
         * Derive encryption key from master password using PBKDF2
         */
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );
        
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        
        return key;
    }
    
    static async encrypt(text, key) {
        /**
         * Encrypt text using AES-GCM
         * Returns base64-encoded: iv + encrypted data
         */
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );
        
        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        
        // Convert to base64
        return btoa(String.fromCharCode(...combined));
    }
    
    static async decrypt(encryptedBase64, key) {
        /**
         * Decrypt base64-encoded encrypted data
         */
        // Decode base64
        const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        
        // Extract IV and encrypted data
        const iv = combined.slice(0, 12);
        const data = combined.slice(12);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }
    
    static generateSalt() {
        /**
         * Generate random salt for PBKDF2
         */
        return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    }
    
    static saltToBase64(salt) {
        return btoa(String.fromCharCode(...salt));
    }
    
    static base64ToSalt(base64) {
        return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    }
}

// State Management
let currentView = 'login';
let authToken = null;
let currentUser = null;
let encryptionKey = null; // Client-side encryption key derived from master password
let loginSessionToken = null; // Temporary token for login verification
let loginPassword = null; // Store password temporarily for encryption key derivation
let currentRecordId = null; // Track the current record being viewed/edited

// DOM Elements
const views = {
    login: document.getElementById('loginView'),
    signup: document.getElementById('signupView'),
    verify: document.getElementById('verifyView'),
    loginVerify: document.getElementById('loginVerifyView'),
    forgotPassword: document.getElementById('forgotPasswordView'),
    signedIn: document.getElementById('signedInView'),
    record: document.getElementById('recordView')
};

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    // Check if user is already logged in
    const stored = await chrome.storage.local.get(['authToken', 'userEmail', 'loginSessionToken', 'loginEmail', 'loginPassword', 'pendingVerificationEmail', 'encryptionKey']);
    
    if (stored.authToken) {
        // User is fully logged in
        authToken = stored.authToken;
        currentUser = stored.userEmail;
        
        // Re-import the encryption key
        if (stored.encryptionKey) {
            const keyData = JSON.parse(stored.encryptionKey);
            encryptionKey = await crypto.subtle.importKey(
                'raw',
                new Uint8Array(keyData),
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
        }
        
        showView('signedIn');
    } else if (stored.loginSessionToken && stored.loginEmail && stored.loginPassword) {
        // User is in the middle of login verification
        loginSessionToken = stored.loginSessionToken;
        currentUser = stored.loginEmail;
        loginPassword = stored.loginPassword;
        document.getElementById('loginVerificationCode').value = '';
        document.getElementById('loginVerifyError').textContent = '';
        showView('loginVerify');
    } else if (stored.pendingVerificationEmail) {
        // User is in the middle of signup email verification
        document.getElementById('verificationCode').value = '';
        document.getElementById('verifyError').textContent = '';
        document.getElementById('verifySuccess').textContent = '';
        showView('verify');
    }

    setupEventListeners();
    
    // Close menu dropdown when clicking outside
    document.addEventListener('click', (e) => {
        const menuDropdown = document.getElementById('menuDropdown');
        const menuBtn = document.getElementById('menuBtn');
        const recordMenuDropdown = document.getElementById('recordMenuDropdown');
        const recordMenuBtn = document.getElementById('recordMenuBtn');
        const loginMenuDropdown = document.getElementById('loginMenuDropdown');
        const loginMenuBtn = document.getElementById('loginMenuBtn');
        
        if (menuDropdown && menuBtn && !menuBtn.contains(e.target) && !menuDropdown.contains(e.target)) {
            menuDropdown.classList.remove('active');
        }
        
        if (recordMenuDropdown && recordMenuBtn && !recordMenuBtn.contains(e.target) && !recordMenuDropdown.contains(e.target)) {
            recordMenuDropdown.classList.remove('active');
        }
        
        if (loginMenuDropdown && loginMenuBtn && !loginMenuBtn.contains(e.target) && !loginMenuDropdown.contains(e.target)) {
            loginMenuDropdown.classList.remove('active');
        }
    });
});

// View Management
function showView(viewName) {
    Object.keys(views).forEach(key => {
        views[key].classList.remove('active');
    });
    views[viewName].classList.add('active');
    currentView = viewName;
    
    // Load vault when showing signed in view
    if (viewName === 'signedIn') {
        loadVault();
    }
}

// Event Listeners
function setupEventListeners() {
    // Login View
    document.getElementById('loginBtn').addEventListener('click', handleLogin);
    document.getElementById('showSignupBtn').addEventListener('click', () => showView('signup'));
    document.getElementById('loginMenuBtn').addEventListener('click', (e) => {
        e.stopPropagation();
        document.getElementById('loginMenuDropdown').classList.toggle('active');
    });
    document.getElementById('menuForgotPasswordBtn').addEventListener('click', () => {
        document.getElementById('forgotPasswordEmail').value = '';
        document.getElementById('forgotPasswordError').textContent = '';
        showView('forgotPassword');
    });

    // Forgot Password View
    document.getElementById('sendResetCodeBtn').addEventListener('click', handleSendResetCode);
    document.getElementById('backToLoginFromForgotBtn').addEventListener('click', () => showView('login'));

    // Signup View
    document.getElementById('signupBtn').addEventListener('click', handleSignup);
    document.getElementById('showLoginBtn').addEventListener('click', () => showView('login'));

    // Verification View
    document.getElementById('verifyBtn').addEventListener('click', handleVerifyEmail);
    document.getElementById('resendCodeBtn').addEventListener('click', handleResendCode);

    // Login Verification View
    document.getElementById('verifyLoginBtn').addEventListener('click', handleVerifyLogin);
    document.getElementById('backToLoginFromVerifyBtn').addEventListener('click', async () => {
        // Clear login session data when user goes back
        await chrome.storage.local.remove(['loginSessionToken', 'loginEmail', 'loginPassword']);
        loginSessionToken = null;
        loginPassword = null;
        currentUser = null;
        showView('login');
    });

    // Signed In View
    document.getElementById('menuBtn').addEventListener('click', (e) => {
        e.stopPropagation();
        document.getElementById('menuDropdown').classList.toggle('active');
    });
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    document.getElementById('addRecordBtn').addEventListener('click', async () => {
        clearRecordForm();
        showView('record');
        // Auto-generate a password when opening the form
        await handleGenerateForRecord();
    });
    document.getElementById('vaultSearchInput').addEventListener('input', handleVaultSearch);

    // Record View
    document.getElementById('recordMenuBtn').addEventListener('click', (e) => {
        e.stopPropagation();
        document.getElementById('recordMenuDropdown').classList.toggle('active');
    });
    document.getElementById('recordLogoutBtn').addEventListener('click', handleLogout);
    document.getElementById('savePasswordBtn').addEventListener('click', handleSavePassword);
    document.getElementById('generatePasswordIcon').addEventListener('click', handleGenerateForRecord);
    document.getElementById('backToVaultBtn').addEventListener('click', () => {
        showView('signedIn');
        loadVault();
    });

    // Enter key handlers
    document.getElementById('loginPassword').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleLogin();
    });
    document.getElementById('signupPasswordConfirm').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleSignup();
    });
}

// Authentication Functions
async function handleLogin() {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const errorEl = document.getElementById('loginError');

    errorEl.textContent = '';

    if (!email || !password) {
        errorEl.textContent = 'Please fill in all fields';
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Invalid credentials');
        }

        const data = await response.json();
        loginSessionToken = data.session_token;
        currentUser = email;
        loginPassword = password; // Store temporarily for encryption key derivation

        // Store the salt from server response
        if (data.encryption_salt) {
            await chrome.storage.local.set({ userSalt: data.encryption_salt });
        }

        // Store login session state so user can resume if they close the extension
        await chrome.storage.local.set({
            loginSessionToken: loginSessionToken,
            loginEmail: email,
            loginPassword: password
        });

        // Show login verification view
        document.getElementById('loginVerificationCode').value = '';
        document.getElementById('loginVerifyError').textContent = '';
        showView('loginVerify');
    } catch (error) {
        errorEl.textContent = error.message || 'Login failed. Please try again.';
    }
}

async function handleVerifyLogin() {
    const code = document.getElementById('loginVerificationCode').value.trim();
    const errorEl = document.getElementById('loginVerifyError');

    errorEl.textContent = '';

    if (!code || code.length !== 6) {
        errorEl.textContent = 'Please enter the 6-digit code';
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/verify-login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                email: currentUser,
                code: code,
                session_token: loginSessionToken
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Invalid verification code');
        }

        const data = await response.json();
        authToken = data.access_token;

        // Derive encryption key from password and stored salt
        const storedData = await chrome.storage.local.get(['userSalt']);
        let salt;
        
        if (storedData.userSalt) {
            salt = CryptoManager.base64ToSalt(storedData.userSalt);
        } else {
            // Generate salt if not exists (first time login)
            salt = CryptoManager.generateSalt();
            await chrome.storage.local.set({ userSalt: CryptoManager.saltToBase64(salt) });
        }
        
        encryptionKey = await CryptoManager.deriveKey(loginPassword, salt);

        // Export and store the encryption key
        const exportedKey = await crypto.subtle.exportKey('raw', encryptionKey);
        const keyArray = Array.from(new Uint8Array(exportedKey));

        // Store token and key
        await chrome.storage.local.set({ 
            authToken: authToken,
            userEmail: currentUser,
            encryptionKey: JSON.stringify(keyArray)
        });
        
        // Clear login session data
        await chrome.storage.local.remove(['loginSessionToken', 'loginEmail', 'loginPassword']);
        
        loginSessionToken = null;
        loginPassword = null;

        showView('signedIn');
    } catch (error) {
        errorEl.textContent = error.message || 'Verification failed. Please try again.';
    }
}

async function handleSendResetCode() {
    const email = document.getElementById('forgotPasswordEmail').value.trim();
    const errorEl = document.getElementById('forgotPasswordError');

    errorEl.textContent = '';

    if (!email) {
        errorEl.textContent = 'Please enter your email address';
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/forgot-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to send reset code');
        }

        // TODO: Navigate to reset password verification view
        // For now, show success message
        errorEl.style.color = '#10a37f';
        errorEl.textContent = 'Reset code sent! Please check your email.';
        
    } catch (error) {
        errorEl.style.color = '#ef4444';
        errorEl.textContent = error.message || 'Failed to send reset code. Please try again.';
    }
}

async function handleSignup() {
    const email = document.getElementById('signupEmail').value.trim();
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupPasswordConfirm').value;
    const errorEl = document.getElementById('signupError');

    errorEl.textContent = '';

    if (!email || !password || !confirmPassword) {
        errorEl.textContent = 'Please fill in all fields';
        return;
    }

    if (password !== confirmPassword) {
        errorEl.textContent = 'Passwords do not match';
        return;
    }

    if (password.length < 8) {
        errorEl.textContent = 'Password must be at least 8 characters';
        return;
    }

    try {
        // Generate and store salt for this user
        const salt = CryptoManager.generateSalt();
        const saltBase64 = CryptoManager.saltToBase64(salt);
        
        const response = await fetch(`${API_BASE_URL}/api/auth/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                email, 
                password,
                encryption_salt: saltBase64
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.detail || 'Signup failed');
        }

        // Store salt locally as backup
        await chrome.storage.local.set({ 
            pendingVerificationEmail: email,
            userSalt: saltBase64
        });
        
        // Show verification view
        document.getElementById('verificationCode').value = '';
        document.getElementById('verifyError').textContent = '';
        showView('verify');
        
    } catch (error) {
        errorEl.textContent = error.message || 'Signup failed. Please try again.';
    }
}

async function handleLogout() {
    authToken = null;
    currentUser = null;
    encryptionKey = null; // Clear encryption key from memory
    await chrome.storage.local.remove(['authToken', 'userEmail', 'encryptionKey']);
    
    // Clear form fields
    document.getElementById('loginEmail').value = '';
    document.getElementById('loginPassword').value = '';
    
    showView('login');
}

// Email Verification Functions
async function handleVerifyEmail() {
    const stored = await chrome.storage.local.get(['pendingVerificationEmail']);
    const email = stored.pendingVerificationEmail;
    const code = document.getElementById('verificationCode').value.trim();
    const errorEl = document.getElementById('verifyError');
    const successEl = document.getElementById('verifySuccess');

    errorEl.textContent = '';
    successEl.textContent = '';

    if (!code || code.length !== 6) {
        errorEl.textContent = 'Please enter the 6-digit code';
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/verify-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, code })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Verification failed');
        }

        // Clear pending verification state
        await chrome.storage.local.remove('pendingVerificationEmail');
        
        // Redirect to login immediately
        document.getElementById('verificationCode').value = '';
        showView('login');
        
    } catch (error) {
        errorEl.textContent = error.message || 'Verification failed. Please try again.';
    }
}

async function handleResendCode() {
    const stored = await chrome.storage.local.get(['pendingVerificationEmail']);
    const email = stored.pendingVerificationEmail;
    const errorEl = document.getElementById('verifyError');
    const successEl = document.getElementById('verifySuccess');

    errorEl.textContent = '';
    successEl.textContent = '';

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/resend-verification`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(email)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Failed to resend code');
        }

        successEl.textContent = 'Verification code resent! Check your email.';
        
    } catch (error) {
        errorEl.textContent = error.message || 'Failed to resend code. Please try again.';
    }
}

// Vault Functions
function clearRecordForm() {
    document.getElementById('saveWebsite').value = '';
    document.getElementById('saveUsername').value = '';
    document.getElementById('savePassword').value = '';
    document.getElementById('saveError').textContent = '';
    document.getElementById('saveSuccess').textContent = '';
    currentRecordId = null; // Clear the current record ID
}

async function handleGenerateForRecord() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/passwords/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                length: 16,
                include_uppercase: true,
                include_lowercase: true,
                include_digits: true,
                include_symbols: true
            })
        });

        const data = await response.json();
        document.getElementById('savePassword').value = data.password;
    } catch (error) {
        console.error('Failed to generate password:', error);
    }
}

async function loadVault() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/vault/list`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load passwords');
        }

        const data = await response.json();
        displayVaultRecords(data.passwords);
    } catch (error) {
        console.error('Failed to load vault:', error);
    }
}

function displayVaultRecords(passwords) {
    const vaultList = document.getElementById('vaultList');
    
    if (!passwords || passwords.length === 0) {
        vaultList.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                    </svg>
                </div>
                <div class="empty-state-message">
                    No passwords yet.<br>
                    Click (+) to add your first.
                </div>
            </div>
        `;
        return;
    }

    // Sort alphabetically by website
    passwords.sort((a, b) => a.website.localeCompare(b.website));

    vaultList.innerHTML = passwords.map(password => `
        <div class="vault-record" data-id="${password.id}">
            <div class=\"vault-record-title\">${escapeHtml(password.website)}</div>
            <div class=\"vault-record-username\">${escapeHtml(password.username)}</div>
        </div>
    `).join('');

    // Add click handlers to records
    vaultList.querySelectorAll('.vault-record').forEach(record => {
        record.addEventListener('click', () => viewRecord(record.dataset.id, passwords));
    });
}

function handleVaultSearch(e) {
    const searchTerm = e.target.value.toLowerCase();
    const records = document.querySelectorAll('.vault-record');
    
    records.forEach(record => {
        const title = record.querySelector('.vault-record-title').textContent.toLowerCase();
        const username = record.querySelector('.vault-record-username').textContent.toLowerCase();
        
        if (title.includes(searchTerm) || username.includes(searchTerm)) {
            record.style.display = 'block';
        } else {
            record.style.display = 'none';
        }
    });
}

async function viewRecord(passwordId, passwords) {
    const password = passwords.find(p => p.id === passwordId);
    if (!password) return;

    // Decrypt and show password details
    try {
        if (!encryptionKey) {
            console.error('Encryption key not available. Please logout and login again.');
            return;
        }
        
        const decryptedPassword = await CryptoManager.decrypt(password.password, encryptionKey);
        
        // Populate the record form
        document.getElementById('saveWebsite').value = password.website;
        document.getElementById('saveUsername').value = password.username;
        document.getElementById('savePassword').value = decryptedPassword;
        document.getElementById('saveError').textContent = '';
        document.getElementById('saveSuccess').textContent = '';
        
        // Store the current record ID for potential updates
        currentRecordId = passwordId;
        
        // Show the record view
        showView('record');
    } catch (error) {
        console.error('Failed to decrypt password:', error);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function handleSavePassword() {
    const website = document.getElementById('saveWebsite').value.trim();
    const username = document.getElementById('saveUsername').value.trim();
    const password = document.getElementById('savePassword').value.trim();
    const errorEl = document.getElementById('saveError');
    const successEl = document.getElementById('saveSuccess');

    errorEl.textContent = '';
    successEl.textContent = '';

    if (!website || !username || !password) {
        errorEl.textContent = 'Website, username, and password are required';
        return;
    }

    if (!encryptionKey) {
        errorEl.textContent = 'Encryption key not available. Please log in again.';
        return;
    }

    try {
        // Encrypt password on client side
        const encryptedPassword = await CryptoManager.encrypt(password, encryptionKey);
        
        // If updating an existing record, delete the old one first
        if (currentRecordId) {
            await fetch(`${API_BASE_URL}/api/vault/${currentRecordId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });
        }
        
        const response = await fetch(`${API_BASE_URL}/api/vault/save`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                website,
                username,
                password: encryptedPassword // Send encrypted
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Failed to save password');
        }

        // Clear form and go back to vault
        clearRecordForm();
        showView('signedIn');
        loadVault();
        
    } catch (error) {
        errorEl.textContent = error.message || 'Failed to save password';
    }
}

async function deletePassword(passwordId) {
    if (!confirm('Are you sure you want to delete this password?')) {
        return;
    }

    try {
        await fetch(`${API_BASE_URL}/api/vault/${passwordId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        loadVault();
    } catch (error) {
        console.error('Failed to delete password:', error);
    }
}

// Utility Functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
