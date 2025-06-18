import os
import uuid
import json
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pymongo import MongoClient
import base64
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Secure Password Manager")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security setup
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MongoDB setup
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb+srv://user:new_pass@cluster0.xngqakh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
DB_NAME = os.environ.get('DB_NAME', 'password_manager')

try:
    client = MongoClient(MONGO_URL)
    db = client[DB_NAME]
    users_collection = db.users
    passwords_collection = db.passwords
    folders_collection = db.folders
    print("Connected to MongoDB successfully")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Server-side encryption key (for additional security layer)
SERVER_ENCRYPTION_KEY = os.environ.get('SERVER_ENCRYPTION_KEY', Fernet.generate_key().decode())
server_cipher = Fernet(SERVER_ENCRYPTION_KEY.encode() if isinstance(SERVER_ENCRYPTION_KEY, str) else SERVER_ENCRYPTION_KEY)

# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class MasterPasswordAuth(BaseModel):
    master_password: str

class FolderCreate(BaseModel):
    name: str
    color: Optional[str] = "#3B82F6"

class PasswordEntryCreate(BaseModel):
    title: str
    website_url: Optional[str] = ""
    username: str
    encrypted_password: str  # This comes already encrypted from client
    notes: Optional[str] = ""
    folder_id: Optional[str] = None

class PasswordEntryUpdate(BaseModel):
    title: Optional[str] = None
    website_url: Optional[str] = None
    username: Optional[str] = None
    encrypted_password: Optional[str] = None
    notes: Optional[str] = None
    folder_id: Optional[str] = None

# Utility functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def encrypt_server_side(data: str) -> str:
    """Additional server-side encryption layer"""
    return server_cipher.encrypt(data.encode()).decode()

def decrypt_server_side(encrypted_data: str) -> str:
    """Decrypt server-side encryption layer"""
    return server_cipher.decrypt(encrypted_data.encode()).decode()

# API Routes

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "message": "Password Manager API is running"}

@app.post("/api/auth/register")
async def register_user(user_data: UserRegister):
    # Check if user already exists
    existing_user = users_collection.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    user_id = str(uuid.uuid4())
    hashed_password = hash_password(user_data.password)
    
    user_doc = {
        "user_id": user_id,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "password_hash": hashed_password,
        "created_at": datetime.now(timezone.utc),
        "master_password_set": False
    }
    
    users_collection.insert_one(user_doc)
    
    # Create access token
    access_token = create_access_token(data={"sub": user_id})
    
    return {
        "message": "User registered successfully",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "user_id": user_id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "master_password_set": False
        }
    }

@app.post("/api/auth/login")
async def login_user(user_data: UserLogin):
    # Find user
    user = users_collection.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Create access token
    access_token = create_access_token(data={"sub": user["user_id"]})
    
    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "user_id": user["user_id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "master_password_set": user.get("master_password_set", False)
        }
    }

@app.post("/api/auth/set-master-password")
async def set_master_password(
    master_data: MasterPasswordAuth,
    current_user: str = Depends(get_current_user)
):
    # Hash the master password for verification purposes
    master_password_hash = hash_password(master_data.master_password)
    
    # Update user with master password
    users_collection.update_one(
        {"user_id": current_user},
        {
            "$set": {
                "master_password_hash": master_password_hash,
                "master_password_set": True,
                "master_password_updated_at": datetime.now(timezone.utc)
            }
        }
    )
    
    return {"message": "Master password set successfully"}

@app.post("/api/auth/verify-master-password")
async def verify_master_password(
    master_data: MasterPasswordAuth,
    current_user: str = Depends(get_current_user)
):
    # Get user's master password hash
    user = users_collection.find_one({"user_id": current_user})
    if not user or not user.get("master_password_set"):
        raise HTTPException(status_code=400, detail="Master password not set")
    
    # Verify master password
    if not verify_password(master_data.master_password, user["master_password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid master password")
    
    return {"message": "Master password verified", "verified": True}

@app.get("/api/folders")
async def get_folders(current_user: str = Depends(get_current_user)):
    folders = list(folders_collection.find(
        {"user_id": current_user},
        {"_id": 0, "folder_id": 1, "name": 1, "color": 1, "created_at": 1}
    ))
    return {"folders": folders}

@app.post("/api/folders")
async def create_folder(
    folder_data: FolderCreate,
    current_user: str = Depends(get_current_user)
):
    folder_id = str(uuid.uuid4())
    folder_doc = {
        "folder_id": folder_id,
        "user_id": current_user,
        "name": folder_data.name,
        "color": folder_data.color,
        "created_at": datetime.now(timezone.utc)
    }
    
    folders_collection.insert_one(folder_doc)
    
    return {
        "message": "Folder created successfully",
        "folder": {
            "folder_id": folder_id,
            "name": folder_data.name,
            "color": folder_data.color,
            "created_at": folder_doc["created_at"]
        }
    }

@app.get("/api/passwords")
async def get_passwords(
    folder_id: Optional[str] = None,
    search: Optional[str] = None,
    current_user: str = Depends(get_current_user)
):
    # Build query
    query = {"user_id": current_user}
    if folder_id:
        query["folder_id"] = folder_id
    
    # Get passwords
    passwords = list(passwords_collection.find(
        query,
        {"_id": 0}
    ))
    
    # Decrypt server-side encryption and search
    decrypted_passwords = []
    for password in passwords:
        try:
            # Decrypt the server-side encryption layer
            decrypted_password = decrypt_server_side(password["encrypted_password"])
            password["encrypted_password"] = decrypted_password
            
            # Apply search filter if provided
            if search:
                search_lower = search.lower()
                if (search_lower in password["title"].lower() or 
                    search_lower in password.get("website_url", "").lower() or
                    search_lower in password["username"].lower() or
                    search_lower in password.get("notes", "").lower()):
                    decrypted_passwords.append(password)
            else:
                decrypted_passwords.append(password)
        except Exception as e:
            print(f"Error decrypting password entry: {e}")
            continue
    
    return {"passwords": decrypted_passwords}

@app.post("/api/passwords")
async def create_password_entry(
    password_data: PasswordEntryCreate,
    current_user: str = Depends(get_current_user)
):
    # Add server-side encryption layer
    double_encrypted_password = encrypt_server_side(password_data.encrypted_password)
    
    password_id = str(uuid.uuid4())
    password_doc = {
        "password_id": password_id,
        "user_id": current_user,
        "title": password_data.title,
        "website_url": password_data.website_url,
        "username": password_data.username,
        "encrypted_password": double_encrypted_password,  # Double encrypted
        "notes": password_data.notes,
        "folder_id": password_data.folder_id,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    
    passwords_collection.insert_one(password_doc)
    
    return {
        "message": "Password entry created successfully",
        "password_id": password_id
    }

@app.put("/api/passwords/{password_id}")
async def update_password_entry(
    password_id: str,
    password_data: PasswordEntryUpdate,
    current_user: str = Depends(get_current_user)
):
    # Check if password entry exists and belongs to user
    existing_entry = passwords_collection.find_one({
        "password_id": password_id,
        "user_id": current_user
    })
    
    if not existing_entry:
        raise HTTPException(status_code=404, detail="Password entry not found")
    
    # Build update data
    update_data = {"updated_at": datetime.now(timezone.utc)}
    
    for field, value in password_data.model_dump(exclude_unset=True).items():
        if field == "encrypted_password" and value:
            # Add server-side encryption layer
            update_data[field] = encrypt_server_side(value)
        else:
            update_data[field] = value
    
    passwords_collection.update_one(
        {"password_id": password_id, "user_id": current_user},
        {"$set": update_data}
    )
    
    return {"message": "Password entry updated successfully"}

@app.delete("/api/passwords/{password_id}")
async def delete_password_entry(
    password_id: str,
    current_user: str = Depends(get_current_user)
):
    result = passwords_collection.delete_one({
        "password_id": password_id,
        "user_id": current_user
    })
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Password entry not found")
    
    return {"message": "Password entry deleted successfully"}

@app.delete("/api/folders/{folder_id}")
async def delete_folder(
    folder_id: str,
    current_user: str = Depends(get_current_user)
):
    # Check if folder exists
    folder = folders_collection.find_one({
        "folder_id": folder_id,
        "user_id": current_user
    })
    
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    
    # Move all passwords in this folder to no folder
    passwords_collection.update_many(
        {"folder_id": folder_id, "user_id": current_user},
        {"$unset": {"folder_id": ""}}
    )
    
    # Delete folder
    folders_collection.delete_one({
        "folder_id": folder_id,
        "user_id": current_user
    })
    
    return {"message": "Folder deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
