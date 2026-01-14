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

// Listen for form submissions to offer saving passwords
document.addEventListener('submit', async (e) => {
    const form = e.target;
    const fields = detectPasswordFields();
    
    if (fields.hasPasswordField && fields.hasEmailField) {
        const emailField = fields.emailFields[0];
        const passwordField = fields.passwordFields[0];
        
        const email = emailField.value;
        const password = passwordField.value;
        const website = window.location.hostname;
        
        if (email && password) {
            // Send message to background script to save password
            chrome.runtime.sendMessage({
                action: 'savePassword',
                data: {
                    website: website,
                    username: email,
                    password: password
                }
            }, (response) => {
                if (response && response.success) {
                    console.log('Password saved successfully');
                }
            });
        }
    }
});

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
