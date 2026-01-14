from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import secrets
import string
import hashlib
import os
from datetime import datetime, timedelta, UTC
from contextlib import asynccontextmanager
from decimal import Decimal
import json
from jose import jwt
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

####################################################################################################
# APPLICATION LIFESPAN MANAGEMENT
####################################################################################################

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize application on startup."""
    print("[STARTUP] Initializing Password Manager API...")
    create_dynamodb_tables()
    print("[STARTUP] DynamoDB tables ready")
    yield
    print("[SHUTDOWN] Password Manager API shutting down...")

####################################################################################################
# CORE APPLICATION CONFIGURATION
####################################################################################################

app = FastAPI(title="Password Manager API", lifespan=lifespan)

# CORS configuration for Chrome extension (allow all origins for local development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for local development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# AWS service configuration
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID', '')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY', '')

# DynamoDB table configuration
DYNAMODB_ENDPOINT = os.getenv('DYNAMODB_ENDPOINT', None)
DYNAMODB_USER_TABLE = os.getenv('DYNAMODB_USER_TABLE', 'password_manager_users')
DYNAMODB_PASSWORDS_TABLE = os.getenv('DYNAMODB_PASSWORDS_TABLE', 'password_manager_passwords')

####################################################################################################
# DYNAMODB CONFIGURATION AND UTILITIES
####################################################################################################

class DecimalEncoder(json.JSONEncoder):
    """Custom JSON encoder for DynamoDB Decimal types."""
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        return super(DecimalEncoder, self).default(o)

def get_dynamodb_resource():
    """Get DynamoDB resource connection."""
    return boto3.resource(
        'dynamodb',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        endpoint_url=DYNAMODB_ENDPOINT
    )

def get_dynamodb_client():
    """Get DynamoDB client for table management."""
    return boto3.client(
        'dynamodb',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        endpoint_url=DYNAMODB_ENDPOINT
    )

def create_dynamodb_tables():
    """Initialize all required DynamoDB tables with indexes."""
    dynamodb = get_dynamodb_client()
    existing_tables = dynamodb.list_tables()['TableNames']
    
    # Users table: Core user account storage with email lookup capability
    if DYNAMODB_USER_TABLE not in existing_tables:
        try:
            dynamodb.create_table(
                TableName=DYNAMODB_USER_TABLE,
                KeySchema=[
                    {'AttributeName': 'user_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'user_id', 'AttributeType': 'S'},
                    {'AttributeName': 'email', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'email-index',
                        'KeySchema': [{'AttributeName': 'email', 'KeyType': 'HASH'}],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                    }
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
            print(f"[DB] Created table: {DYNAMODB_USER_TABLE}")
        except Exception as e:
            print(f"[DB] Error creating {DYNAMODB_USER_TABLE}: {e}")
    
    # Passwords table: Store encrypted password entries
    if DYNAMODB_PASSWORDS_TABLE not in existing_tables:
        try:
            dynamodb.create_table(
                TableName=DYNAMODB_PASSWORDS_TABLE,
                KeySchema=[
                    {'AttributeName': 'user_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'password_id', 'KeyType': 'RANGE'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'user_id', 'AttributeType': 'S'},
                    {'AttributeName': 'password_id', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
            print(f"[DB] Created table: {DYNAMODB_PASSWORDS_TABLE}")
        except Exception as e:
            print(f"[DB] Error creating {DYNAMODB_PASSWORDS_TABLE}: {e}")

####################################################################################################
# DYNAMODB MODEL CLASSES
####################################################################################################

class DynamoDBUser:
    """User model for DynamoDB operations."""
    
    @staticmethod
    def create(email: str, password_hash: str, verification_code: str, encryption_salt: str = None):
        """Create a new user in DynamoDB."""
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_USER_TABLE)
        
        user_id = str(secrets.token_urlsafe(16))
        timestamp = datetime.now(UTC).isoformat()
        
        item = {
            'user_id': user_id,
            'email': email,
            'password_hash': password_hash,
            'email_verified': False,
            'verification_code': verification_code,
            'created_at': timestamp,
            'updated_at': timestamp
        }
        
        if encryption_salt:
            item['encryption_salt'] = encryption_salt
        
        table.put_item(Item=item)
        return item
    
    @staticmethod
    def get_by_email(email: str):
        """Fetch user by email using GSI."""
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_USER_TABLE)
        
        response = table.query(
            IndexName='email-index',
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        
        items = response.get('Items', [])
        return items[0] if items else None
    
    @staticmethod
    def get_by_id(user_id: str):
        """Fetch user by user_id."""
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_USER_TABLE)
        
        response = table.get_item(Key={'user_id': user_id})
        return response.get('Item')
    
    @staticmethod
    def verify_email(email: str, code: str):
        """Verify user's email with code."""
        user = DynamoDBUser.get_by_email(email)
        if not user:
            return False
        
        if user.get('verification_code') != code:
            return False
        
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_USER_TABLE)
        
        table.update_item(
            Key={'user_id': user['user_id']},
            UpdateExpression='SET email_verified = :verified, updated_at = :updated',
            ExpressionAttributeValues={
                ':verified': True,
                ':updated': datetime.now(UTC).isoformat()
            }
        )
        return True
    
    @staticmethod
    def update_verification_code(email: str, new_code: str):
        """Update verification code for resend."""
        user = DynamoDBUser.get_by_email(email)
        if not user:
            return False
        
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_USER_TABLE)
        
        table.update_item(
            Key={'user_id': user['user_id']},
            UpdateExpression='SET verification_code = :code, updated_at = :updated',
            ExpressionAttributeValues={
                ':code': new_code,
                ':updated': datetime.now(UTC).isoformat()
            }
        )
        return True
    
    @staticmethod
    def set_login_verification_code(email: str, code: str):
        """Set login verification code (separate from email signup verification)."""
        user = DynamoDBUser.get_by_email(email)
        if not user:
            return False
        
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_USER_TABLE)
        
        # Store code with expiration (5 minutes)
        expiration = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
        
        table.update_item(
            Key={'user_id': user['user_id']},
            UpdateExpression='SET login_verification_code = :code, login_code_expires = :expires, updated_at = :updated',
            ExpressionAttributeValues={
                ':code': code,
                ':expires': expiration,
                ':updated': datetime.now(UTC).isoformat()
            }
        )
        return True
    
    @staticmethod
    def verify_login_code(email: str, code: str):
        """Verify login code and check expiration."""
        user = DynamoDBUser.get_by_email(email)
        if not user:
            return False
        
        # Check if code exists and matches
        if user.get('login_verification_code') != code:
            return False
        
        # Check if code has expired
        expiration = user.get('login_code_expires')
        if not expiration:
            return False
        
        if datetime.fromisoformat(expiration) < datetime.now(UTC):
            return False  # Code expired
        
        # Clear the code after successful verification
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_USER_TABLE)
        table.update_item(
            Key={'user_id': user['user_id']},
            UpdateExpression='REMOVE login_verification_code, login_code_expires SET updated_at = :updated',
            ExpressionAttributeValues={
                ':updated': datetime.now(UTC).isoformat()
            }
        )
        
        return True

class DynamoDBPasswords:
    """Password vault model for DynamoDB operations."""
    
    @staticmethod
    def create(user_id: str, entry: 'PasswordEntry'):
        """Save a password entry to the vault."""
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_PASSWORDS_TABLE)
        
        password_id = str(secrets.token_urlsafe(16))
        timestamp = datetime.now(UTC).isoformat()
        
        item = {
            'user_id': user_id,
            'password_id': password_id,
            'website': entry.website,
            'username': entry.username,
            'password': entry.password,  # Already encrypted client-side
            'created_at': timestamp,
            'updated_at': timestamp
        }

        table.put_item(Item=item)
        return password_id
    
    @staticmethod
    def get_all_by_user(user_id: str):
        """Fetch all passwords for a user."""
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_PASSWORDS_TABLE)
        
        response = table.query(
            KeyConditionExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )
        
        return response.get('Items', [])
    
    @staticmethod
    def delete(user_id: str, password_id: str):
        """Delete a password entry."""
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table(DYNAMODB_PASSWORDS_TABLE)
        
        table.delete_item(
            Key={
                'user_id': user_id,
                'password_id': password_id
            }
        )
        return True

####################################################################################################
# AWS SIMPLE EMAIL SERVICE (SES) HELPER FUNCTIONS
####################################################################################################

def send_email_ses(recipient_email: str, subject: str, html_content: str):
    """Send email using AWS SES."""
    ses_client = boto3.client(
        'ses',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    
    try:
        response = ses_client.send_email(
            Source=os.getenv('SES_SENDER_EMAIL', 'noreply@yourdomain.com'),
            Destination={'ToAddresses': [recipient_email]},
            Message={
                'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                'Body': {'Html': {'Data': html_content, 'Charset': 'UTF-8'}}
            }
        )
        return response
    except ClientError as e:
        print(f"[SES] Error sending email: {e}")
        raise

def generate_verification_code() -> str:
    """Generate 6-digit verification code."""
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def get_email_verification_template(code: str) -> str:
    """HTML template for email verification."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }}
            .code {{ font-size: 32px; font-weight: bold; text-align: center; padding: 20px; background: white; border-radius: 5px; letter-spacing: 5px; color: #4CAF50; }}
            .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Manager</h1>
            </div>
            <div class="content">
                <h2>Verify Your Email</h2>
                <p>Thank you for signing up! Please use the verification code below to complete your registration:</p>
                <div class="code">{code}</div>
                <p>This code will expire in 15 minutes.</p>
                <p>If you didn't create an account, please ignore this email.</p>
            </div>
            <div class="footer">
                <p>Password Manager - Secure Password Storage</p>
            </div>
        </div>
    </body>
    </html>
    """

def get_login_verification_template(code: str) -> str:
    """HTML template for login verification."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #4279D8; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }}
            .code {{ font-size: 32px; font-weight: bold; text-align: center; padding: 20px; background: white; border-radius: 5px; letter-spacing: 5px; color: #4279D8; }}
            .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Manager</h1>
            </div>
            <div class="content">
                <h2>Login Verification</h2>
                <p>A login attempt was made to your account. Please use the verification code below to complete the login:</p>
                <div class="code">{code}</div>
                <p>This code will expire in 5 minutes.</p>
                <p>If you didn't attempt to login, please secure your account immediately.</p>
            </div>
            <div class="footer">
                <p>Password Manager - Secure Password Storage</p>
            </div>
        </div>
    </body>
    </html>
    """

def get_password_reset_template(code: str) -> str:
    """HTML template for password reset."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #4279D8; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }}
            .code {{ font-size: 32px; font-weight: bold; text-align: center; padding: 20px; background: white; border-radius: 5px; letter-spacing: 5px; color: #4279D8; }}
            .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Manager</h1>
            </div>
            <div class="content">
                <h2>Password Reset Request</h2>
                <p>A password reset was requested for your account. Please use the verification code below to reset your password:</p>
                <div class="code">{code}</div>
                <p>This code will expire in 5 minutes.</p>
                <p>If you didn't request a password reset, please ignore this email and secure your account.</p>
            </div>
            <div class="footer">
                <p>Password Manager - Secure Password Storage</p>
            </div>
        </div>
    </body>
    </html>
    """

# ============= Models =============

class UserSignup(BaseModel):
    email: EmailStr
    password: str
    encryption_salt: str  # Base64-encoded salt for client-side encryption

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ForgotPassword(BaseModel):
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginSession(BaseModel):
    session_token: str
    message: str
    email: str
    encryption_salt: Optional[str] = None

class PasswordEntry(BaseModel):
    website: str
    username: str
    password: str

class PasswordGenerate(BaseModel):
    length: int = 16
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_digits: bool = True
    include_symbols: bool = True

# ============= Utility Functions =============

def hash_password(password: str) -> str:
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True
) -> str:
    """Generate a secure random password"""
    characters = ""
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_lowercase:
        characters += string.ascii_lowercase
    if include_digits:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation
    
    if not characters:
        characters = string.ascii_letters + string.digits
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

####################################################################################################
# AUTHENTICATION DEPENDENCY HELPERS
####################################################################################################

async def get_current_user(authorization: Optional[str] = Header(None)):
    """Extract and validate user from JWT token."""
    if not authorization or not authorization.startswith('Bearer '):
        return None
    
    token = authorization.replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get('sub')
        if not email:
            return None
        
        user = DynamoDBUser.get_by_email(email)
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.JWTError:
        return None

async def get_current_user_required(current_user = Depends(get_current_user)):
    """Require authenticated user."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not current_user.get('email_verified'):
        raise HTTPException(status_code=403, detail="Email not verified")
    return current_user

####################################################################################################
# PYDANTIC DATA VALIDATION MODELS
####################################################################################################

class VerifyEmail(BaseModel):
    email: EmailStr
    code: str

class LoginVerify(BaseModel):
    email: EmailStr
    code: str
    session_token: str

####################################################################################################
# FASTAPI ROUTES - AUTHENTICATION
####################################################################################################

@app.get("/")
async def root():
    return {"message": "Password Manager API", "status": "running"}

@app.post("/api/auth/signup")
async def signup(user: UserSignup):
    """Register a new user and send verification email"""
    # Check if user already exists
    existing_user = DynamoDBUser.get_by_email(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Validate password strength
    if len(user.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    # Hash password and generate verification code
    password_hash = hash_password(user.password)
    verification_code = generate_verification_code()
    
    # Create user in DynamoDB
    new_user = DynamoDBUser.create(user.email, password_hash, verification_code, user.encryption_salt)
    
    # Send verification email
    try:
        send_email_ses(
            recipient_email=user.email,
            subject="Password Manager - Verify Your Email",
            html_content=get_email_verification_template(verification_code)
        )
    except Exception as e:
        print(f"[ERROR] Failed to send verification email: {e}")
        # Continue anyway - user can request resend
    
    return {
        "message": "Registration successful. Please check your email for verification code.",
        "email": user.email
    }

@app.post("/api/auth/verify-email")
async def verify_email(data: VerifyEmail):
    """Verify user's email with 6-digit code"""
    success = DynamoDBUser.verify_email(data.email, data.code)
    
    if not success:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    
    return {"message": "Email verified successfully. You can now login."}

@app.post("/api/auth/resend-verification")
async def resend_verification(email: EmailStr):
    """Resend verification code"""
    user = DynamoDBUser.get_by_email(email)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.get('email_verified'):
        raise HTTPException(status_code=400, detail="Email already verified")
    
    # Generate new code
    new_code = generate_verification_code()
    DynamoDBUser.update_verification_code(email, new_code)
    
    # Send email
    try:
        send_email_ses(
            recipient_email=email,
            subject="Password Manager - Verify Your Email",
            html_content=get_email_verification_template(new_code)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send email")
    
    return {"message": "Verification code resent successfully"}

@app.post("/api/auth/login", response_model=LoginSession)
async def login(user: UserLogin):
    """Authenticate user credentials and send login verification code"""
    # Get user from database
    db_user = DynamoDBUser.get_by_email(user.email)
    
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if email is verified
    if not db_user.get('email_verified'):
        raise HTTPException(status_code=403, detail="Email not verified. Please check your email.")
    
    # Verify password
    if hash_password(user.password) != db_user['password_hash']:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate login verification code
    login_code = generate_verification_code()
    DynamoDBUser.set_login_verification_code(user.email, login_code)
    
    # Create temporary session token (valid for 5 minutes)
    session_token = create_access_token(
        data={"sub": user.email, "type": "login_session"},
        expires_delta=timedelta(minutes=5)
    )
    
    # Send verification email
    try:
        send_email_ses(
            recipient_email=user.email,
            subject="Password Manager - Verification Code",
            html_content=get_login_verification_template(login_code)
        )
    except Exception as e:
        print(f"[ERROR] Failed to send login verification email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send verification code")
    
    return {
        "session_token": session_token,
        "message": "Verification code sent to your email",
        "email": user.email,
        "encryption_salt": db_user.get('encryption_salt')
    }

@app.post("/api/auth/verify-login", response_model=Token)
async def verify_login(data: LoginVerify):
    """Verify login code and return access token"""
    # Validate session token
    try:
        payload = jwt.decode(data.session_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get('sub')
        token_type = payload.get('type')
        
        if not email or token_type != 'login_session' or email != data.email:
            raise HTTPException(status_code=401, detail="Invalid session token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please login again.")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid session token")
    
    # Verify the login code
    if not DynamoDBUser.verify_login_code(data.email, data.code):
        raise HTTPException(status_code=400, detail="Invalid or expired verification code")
    
    # Create full access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": data.email}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/forgot-password")
async def forgot_password(data: ForgotPassword):
    """Send password reset code to user's email"""
    # Get user from database
    db_user = DynamoDBUser.get_by_email(data.email)
    
    if not db_user:
        # Don't reveal if email exists or not for security
        return {"message": "If the email exists, a reset code will be sent"}
    
    # Allow password reset even for unverified accounts
    # The reset flow itself provides email verification
    
    # Generate reset code (reuse login verification code mechanism)
    reset_code = generate_verification_code()
    DynamoDBUser.set_login_verification_code(data.email, reset_code)
    
    # Send reset email
    try:
        send_email_ses(
            recipient_email=data.email,
            subject="Password Manager - Password Reset Code",
            html_content=get_password_reset_template(reset_code)
        )
    except Exception as e:
        print(f"[ERROR] Failed to send password reset email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send reset code")
    
    return {"message": "Reset code sent successfully. Please check your email."}

@app.post("/api/passwords/generate")
async def generate_new_password(params: PasswordGenerate):
    """Generate a secure random password"""
    password = generate_password(
        length=params.length,
        include_uppercase=params.include_uppercase,
        include_lowercase=params.include_lowercase,
        include_digits=params.include_digits,
        include_symbols=params.include_symbols
    )
    return {"password": password}

@app.post("/api/vault/save")
async def save_password(
    entry: PasswordEntry,
    current_user = Depends(get_current_user_required)
):
    """Save a password entry to the vault"""
    password_id = DynamoDBPasswords.create(current_user['user_id'], entry)
    
    return {
        "message": "Password saved successfully",
        "id": password_id
    }

@app.get("/api/vault/list")
async def list_passwords(current_user = Depends(get_current_user_required)):
    """Retrieve all password entries for the authenticated user"""
    passwords = DynamoDBPasswords.get_all_by_user(current_user['user_id'])
    
    # Return encrypted passwords as-is (client will decrypt)
    formatted_passwords = [
        {
            'id': p['password_id'],
            'website': p['website'],
            'username': p['username'],
            'password': p['password'],  # Still encrypted
            'created_at': p['created_at']
        }
        for p in passwords
    ]
    
    return {"passwords": formatted_passwords}

@app.delete("/api/vault/{password_id}")
async def delete_password(
    password_id: str,
    current_user = Depends(get_current_user_required)
):
    """Delete a password entry"""
    DynamoDBPasswords.delete(current_user['user_id'], password_id)
    return {"message": "Password deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
