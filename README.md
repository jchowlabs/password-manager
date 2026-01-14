# Password Manager

A secure password manager with email verification, encrypted storage, and Chrome extension interface.

## Project Structure

```
password-manager/
├── backend/          # FastAPI backend with DynamoDB and SES
│   ├── app.py
│   ├── requirements.txt
│   └── .env
└── extension/        # Chrome extension
    ├── manifest.json
    ├── popup.html
    ├── popup.js
    ├── background.js
    └── content.js
```

## Quick Start

### 1. Backend Setup

```bash
cd backend
pip install -r requirements.txt
python app.py
```

API runs at `http://localhost:8000`

**What it does:**
- FastAPI REST API with JWT authentication
- Email verification via AWS SES (6-digit codes)
- Password encryption using Fernet
- DynamoDB for user accounts and encrypted password vault
- Auto-creates DynamoDB tables on startup

**Environment Setup:**
Configure `.env` with your AWS credentials:
- AWS credentials (same account as your other projects)
- DynamoDB table names
- SES sender email (must be verified in AWS console)
- Encryption key (auto-generates on first run - save it!)

### 2. Extension Setup

```bash
# In Chrome
1. Go to chrome://extensions/
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the extension/ folder
```

**What it does:**
- Popup interface with login/signup/verification flows
- Password generator with customizable options
- Encrypted password vault (view/save/delete)
- Communicates with backend API via JWT tokens
- Auto-saves authentication state

## Features

- ✅ User registration with email verification
- ✅ Secure authentication (JWT tokens)
- ✅ Password encryption (Fernet symmetric encryption)
- ✅ Password generation (customizable length/characters)
- ✅ Password vault (CRUD operations)
- ✅ Chrome extension interface

## API Endpoints

**Authentication:**
- `POST /api/auth/signup` - Register user, sends verification email
- `POST /api/auth/verify-email` - Verify email with 6-digit code
- `POST /api/auth/resend-verification` - Resend verification code
- `POST /api/auth/login` - Login and get JWT token

**Password Management:**
- `POST /api/passwords/generate` - Generate secure password
- `POST /api/vault/save` - Save encrypted password entry
- `GET /api/vault/list` - List user's passwords (decrypted)
- `DELETE /api/vault/{id}` - Delete password entry

## Security

- Passwords encrypted before storage in DynamoDB
- JWT tokens for stateless authentication
- Email verification required for account activation
- HTTPS ready for production deployment
