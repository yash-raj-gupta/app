import requests
import json
import time
import uuid
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Get the backend URL from the frontend .env file
with open('/app/frontend/.env', 'r') as f:
    for line in f:
        if line.startswith('REACT_APP_BACKEND_URL='):
            BACKEND_URL = line.strip().split('=')[1].strip('"\'')
            break

# Ensure the URL doesn't have quotes
BACKEND_URL = BACKEND_URL.strip('"\'')
API_URL = f"{BACKEND_URL}/api"

print(f"Testing backend API at: {API_URL}")

# Test results tracking
test_results = {
    "total": 0,
    "passed": 0,
    "failed": 0,
    "tests": []
}

def log_test(name, passed, details=None):
    """Log test results"""
    global test_results
    test_results["total"] += 1
    if passed:
        test_results["passed"] += 1
        status = "PASSED"
    else:
        test_results["failed"] += 1
        status = "FAILED"
    
    test_results["tests"].append({
        "name": name,
        "status": status,
        "details": details
    })
    
    print(f"[{status}] {name}")
    if details and not passed:
        print(f"  Details: {details}")

def print_summary():
    """Print test summary"""
    print("\n===== TEST SUMMARY =====")
    print(f"Total tests: {test_results['total']}")
    print(f"Passed: {test_results['passed']}")
    print(f"Failed: {test_results['failed']}")
    print(f"Success rate: {(test_results['passed'] / test_results['total']) * 100:.2f}%")
    
    if test_results["failed"] > 0:
        print("\nFailed tests:")
        for test in test_results["tests"]:
            if test["status"] == "FAILED":
                print(f"- {test['name']}")
                if test["details"]:
                    print(f"  Details: {test['details']}")

# Helper function for client-side encryption (simulating frontend encryption)
def derive_key_from_master_password(master_password, salt=None):
    """Derive encryption key from master password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt

def encrypt_password(password, master_password, salt=None):
    """Encrypt password using derived key from master password"""
    key, salt = derive_key_from_master_password(master_password, salt)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(password.encode())
    return base64.b64encode(encrypted).decode(), base64.b64encode(salt).decode()

def decrypt_password(encrypted_password, master_password, salt):
    """Decrypt password using derived key from master password"""
    key, _ = derive_key_from_master_password(master_password, base64.b64decode(salt))
    cipher = Fernet(key)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_password))
    return decrypted.decode()

# Test 1: Health Check
def test_health_check():
    response = requests.get(f"{API_URL}/health")
    if response.status_code == 200 and response.json()["status"] == "healthy":
        log_test("Health Check", True)
        return True
    else:
        log_test("Health Check", False, f"Status code: {response.status_code}, Response: {response.text}")
        return False

# Test 2: User Registration
def test_user_registration():
    # Generate unique email to avoid conflicts
    unique_id = str(uuid.uuid4())[:8]
    email = f"test_user_{unique_id}@example.com"
    
    data = {
        "email": email,
        "password": "SecurePassword123!",
        "full_name": "Test User"
    }
    
    response = requests.post(f"{API_URL}/auth/register", json=data)
    
    if response.status_code == 200 and "access_token" in response.json():
        log_test("User Registration", True)
        return response.json()
    else:
        log_test("User Registration", False, f"Status code: {response.status_code}, Response: {response.text}")
        return None

# Test 3: User Login
def test_user_login(email, password):
    data = {
        "email": email,
        "password": password
    }
    
    response = requests.post(f"{API_URL}/auth/login", json=data)
    
    if response.status_code == 200 and "access_token" in response.json():
        log_test("User Login", True)
        return response.json()
    else:
        log_test("User Login", False, f"Status code: {response.status_code}, Response: {response.text}")
        return None

# Test 4: Invalid Login
def test_invalid_login():
    data = {
        "email": "nonexistent@example.com",
        "password": "WrongPassword123!"
    }
    
    response = requests.post(f"{API_URL}/auth/login", json=data)
    
    if response.status_code == 401:
        log_test("Invalid Login Rejection", True)
        return True
    else:
        log_test("Invalid Login Rejection", False, f"Status code: {response.status_code}, Response: {response.text}")
        return False

# Test 5: Set Master Password
def test_set_master_password(token, master_password):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    data = {
        "master_password": master_password
    }
    
    response = requests.post(f"{API_URL}/auth/set-master-password", json=data, headers=headers)
    
    if response.status_code == 200:
        log_test("Set Master Password", True)
        return True
    else:
        log_test("Set Master Password", False, f"Status code: {response.status_code}, Response: {response.text}")
        return False

# Test 6: Verify Master Password
def test_verify_master_password(token, master_password):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    data = {
        "master_password": master_password
    }
    
    response = requests.post(f"{API_URL}/auth/verify-master-password", json=data, headers=headers)
    
    if response.status_code == 200 and response.json().get("verified") == True:
        log_test("Verify Master Password", True)
        return True
    else:
        log_test("Verify Master Password", False, f"Status code: {response.status_code}, Response: {response.text}")
        return False

# Test 7: Invalid Master Password
def test_invalid_master_password(token):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    data = {
        "master_password": "WrongMasterPassword123!"
    }
    
    response = requests.post(f"{API_URL}/auth/verify-master-password", json=data, headers=headers)
    
    if response.status_code == 401:
        log_test("Invalid Master Password Rejection", True)
        return True
    else:
        log_test("Invalid Master Password Rejection", False, f"Status code: {response.status_code}, Response: {response.text}")
        return False

# Test 8: Create Folder
def test_create_folder(token, folder_name="Test Folder", color="#FF5733"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    data = {
        "name": folder_name,
        "color": color
    }
    
    response = requests.post(f"{API_URL}/folders", json=data, headers=headers)
    
    if response.status_code == 200 and "folder_id" in response.json().get("folder", {}):
        log_test("Create Folder", True)
        return response.json()["folder"]
    else:
        log_test("Create Folder", False, f"Status code: {response.status_code}, Response: {response.text}")
        return None

# Test 9: Get Folders
def test_get_folders(token):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    response = requests.get(f"{API_URL}/folders", headers=headers)
    
    if response.status_code == 200 and "folders" in response.json():
        log_test("Get Folders", True)
        return response.json()["folders"]
    else:
        log_test("Get Folders", False, f"Status code: {response.status_code}, Response: {response.text}")
        return None

# Test 10: Create Password Entry
def test_create_password_entry(token, master_password, folder_id=None):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    # Simulate client-side encryption
    password_to_encrypt = "MySecretPassword123!"
    encrypted_password, salt = encrypt_password(password_to_encrypt, master_password)
    
    data = {
        "title": "Test Password Entry",
        "website_url": "https://example.com",
        "username": "testuser",
        "encrypted_password": f"{encrypted_password}|{salt}",  # Store salt with encrypted password
        "notes": "This is a test password entry",
        "folder_id": folder_id
    }
    
    response = requests.post(f"{API_URL}/passwords", json=data, headers=headers)
    
    if response.status_code == 200 and "password_id" in response.json():
        log_test("Create Password Entry", True)
        return response.json()["password_id"]
    else:
        log_test("Create Password Entry", False, f"Status code: {response.status_code}, Response: {response.text}")
        return None

# Test 11: Get Passwords
def test_get_passwords(token, folder_id=None):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    url = f"{API_URL}/passwords"
    if folder_id:
        url += f"?folder_id={folder_id}"
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200 and "passwords" in response.json():
        log_test("Get Passwords", True)
        return response.json()["passwords"]
    else:
        log_test("Get Passwords", False, f"Status code: {response.status_code}, Response: {response.text}")
        return None

# Test 12: Update Password Entry
def test_update_password_entry(token, password_id, master_password):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    # Simulate client-side encryption for updated password
    new_password = "UpdatedPassword456!"
    encrypted_password, salt = encrypt_password(new_password, master_password)
    
    data = {
        "title": "Updated Password Entry",
        "website_url": "https://updated-example.com",
        "username": "updated_user",
        "encrypted_password": f"{encrypted_password}|{salt}",
        "notes": "This password entry has been updated"
    }
    
    response = requests.put(f"{API_URL}/passwords/{password_id}", json=data, headers=headers)
    
    if response.status_code == 200:
        log_test("Update Password Entry", True)
        return True
    else:
        log_test("Update Password Entry", False, f"Status code: {response.status_code}, Response: {response.text}")
        return False

# Test 13: Search Passwords
def test_search_passwords(token, search_term):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    response = requests.get(f"{API_URL}/passwords?search={search_term}", headers=headers)
    
    if response.status_code == 200 and "passwords" in response.json():
        log_test("Search Passwords", True)
        return response.json()["passwords"]
    else:
        log_test("Search Passwords", False, f"Status code: {response.status_code}, Response: {response.text}")
        return None

# Test 14: Delete Password Entry
def test_delete_password_entry(token, password_id):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    response = requests.delete(f"{API_URL}/passwords/{password_id}", headers=headers)
    
    if response.status_code == 200:
        log_test("Delete Password Entry", True)
        return True
    else:
        log_test("Delete Password Entry", False, f"Status code: {response.status_code}, Response: {response.text}")
        return False

# Test 15: Delete Folder
def test_delete_folder(token, folder_id):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    response = requests.delete(f"{API_URL}/folders/{folder_id}", headers=headers)
    
    if response.status_code == 200:
        log_test("Delete Folder", True)
        return True
    else:
        log_test("Delete Folder", False, f"Status code: {response.status_code}, Response: {response.text}")
        return False

# Test 16: Access Protected Endpoint Without Token
def test_unauthorized_access():
    response = requests.get(f"{API_URL}/folders")
    
    if response.status_code == 403 or response.status_code == 401:
        log_test("Unauthorized Access Rejection", True)
        return True
    else:
        log_test("Unauthorized Access Rejection", False, f"Status code: {response.status_code}, Response: {response.text}")
        return False

# Test 17: User Data Isolation
def test_user_data_isolation(token1, token2, password_id):
    # First, get the password with the first user's token to confirm it exists
    headers1 = {
        "Authorization": f"Bearer {token1}"
    }
    
    response1 = requests.get(f"{API_URL}/passwords", headers=headers1)
    
    if response1.status_code != 200 or "passwords" not in response1.json():
        log_test("User Data Isolation", False, "Failed to get first user's passwords")
        return False
    
    # Check if the password_id is in the first user's passwords
    first_user_passwords = response1.json()["passwords"]
    password_exists = any(p.get("password_id") == password_id for p in first_user_passwords)
    
    if not password_exists:
        log_test("User Data Isolation", False, f"Password ID {password_id} not found in first user's passwords")
        return False
    
    # Now try to get passwords with the second user's token
    headers2 = {
        "Authorization": f"Bearer {token2}"
    }
    
    response2 = requests.get(f"{API_URL}/passwords", headers=headers2)
    
    if response2.status_code != 200 or "passwords" not in response2.json():
        log_test("User Data Isolation", False, "Failed to get second user's passwords")
        return False
    
    # Check if the password_id is NOT in the second user's passwords
    second_user_passwords = response2.json()["passwords"]
    password_not_visible = not any(p.get("password_id") == password_id for p in second_user_passwords)
    
    if password_not_visible:
        log_test("User Data Isolation", True)
        return True
    else:
        log_test("User Data Isolation", False, "Second user can see first user's password")
        return False

# Run all tests
def run_all_tests():
    print("Starting backend API tests...\n")
    
    # Test health check
    if not test_health_check():
        print("Health check failed. Aborting tests.")
        return
    
    # Test user registration and login flow
    user1_data = test_user_registration()
    if not user1_data:
        print("User registration failed. Aborting tests.")
        return
    
    user1_email = user1_data["user"]["email"]
    user1_password = "SecurePassword123!"
    user1_token = user1_data["access_token"]
    
    # Register a second user for isolation testing
    user2_data = test_user_registration()
    if user2_data:
        user2_token = user2_data["access_token"]
    else:
        user2_token = None
    
    # Test login
    login_data = test_user_login(user1_email, user1_password)
    if not login_data:
        print("User login failed. Aborting tests.")
        return
    
    # Test invalid login
    test_invalid_login()
    
    # Test unauthorized access
    test_unauthorized_access()
    
    # Test master password
    master_password = "MasterPassword123!"
    if not test_set_master_password(user1_token, master_password):
        print("Setting master password failed. Aborting tests.")
        return
    
    test_verify_master_password(user1_token, master_password)
    test_invalid_master_password(user1_token)
    
    # Test folder management
    folder = test_create_folder(user1_token)
    if not folder:
        print("Folder creation failed. Aborting tests.")
        return
    
    folder_id = folder["folder_id"]
    test_get_folders(user1_token)
    
    # Test password entry management
    password_id = test_create_password_entry(user1_token, master_password, folder_id)
    if not password_id:
        print("Password entry creation failed. Aborting tests.")
        return
    
    # Create another password entry for search testing
    test_create_password_entry(user1_token, master_password, folder_id)
    
    # Test getting passwords
    test_get_passwords(user1_token)
    test_get_passwords(user1_token, folder_id)
    
    # Test updating password
    test_update_password_entry(user1_token, password_id, master_password)
    
    # Test search
    test_search_passwords(user1_token, "Updated")
    
    # Test user data isolation if we have a second user
    if user2_token:
        test_user_data_isolation(user1_token, user2_token, password_id)
    
    # Test deletion
    test_delete_password_entry(user1_token, password_id)
    test_delete_folder(user1_token, folder_id)
    
    # Print summary
    print_summary()

if __name__ == "__main__":
    run_all_tests()