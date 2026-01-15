// Content Script for Password Manager Extension
// This script runs on all web pages to detect password fields

// Detect password fields on the page
function detectPasswordFields() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const emailInputs = document.querySelectorAll('input[type="email"], input[name*="email"], input[id*="email"]');
    
    return {
        hasPasswordField: passwordInputs.length > 0,
        hasEmailField: emailInputs.length > 0,
        passwordFields: passwordInputs,
        emailFields: emailInputs
    };
}

// TODO: Implement secure password capture with encryption
// Form submission interception disabled for security - passwords must be encrypted client-side first

// Auto-fill functionality (TODO: implement when user selects from vault)
function autoFillPassword(username, password) {
    const fields = detectPasswordFields();
    
    if (fields.hasEmailField && fields.emailFields[0]) {
        fields.emailFields[0].value = username;
    }
    
    if (fields.hasPasswordField && fields.passwordFields[0]) {
        fields.passwordFields[0].value = password;
    }
}

// Listen for messages from popup or background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'autoFill') {
        autoFillPassword(request.username, request.password);
        sendResponse({ success: true });
    }
});
