import streamlit as st
import hashlib
import json
import os
import os
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# Constants
DATA_FILE = "secure_data.json"
USER_FILE = "users.json"
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 60  # seconds
SALT = b'secure_static_salt'

def load_key():
    with open("secret.key", "rb") as f:
        return f.read()
    
# Encryption key
KEY = load_key()
cipher = Fernet(KEY)

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None
    
# Load JSON data
def load_json(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return {}

# Save JSON data
def save_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

stored_data = load_json(DATA_FILE)
users = load_json(USER_FILE)

# Hash passkey
def hash_passkey(passkey):
    dk = hashlib.pbkdf2_hmac(
        'sha256',                   # Hash algorithm
        passkey.encode(),           # Password as bytes
        SALT,                       # Salt
        100_000                    # Iterations
    )
    return base64.b64encode(dk).decode()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        print("❌ Decryption failed:", e)
        return None

# Check lockout status
def is_locked_out():
    if st.session_state.lockout_time:
        elapsed = datetime.now() - st.session_state.lockout_time
        if elapsed < timedelta(seconds=LOCKOUT_TIME):
            remaining = LOCKOUT_TIME - elapsed.total_seconds()
            st.error(f"⏳ Locked out! Try again in {int(remaining)} seconds.")
            return True
        else:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
    return False

# User registration
def register_user(username, password):
    if username in users:
        return False
    users[username] = hash_passkey(password)
    save_json(users, USER_FILE)
    return True

# Authenticate user
def authenticate(username, password):
    return users.get(username) == hash_passkey(password)

# Navigation
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.title("🔐 Secure Data Encryption System")
    st.write("A Streamlit app for storing and retrieving encrypted data securely.")

# Register
elif choice == "Register":
    st.subheader("👤 Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username and password:
            if register_user(username, password):
                st.success("✅ User registered successfully!")
            
            else:
                st.error("❌ Username already exists.")
        else:
            st.warning("Please fill in both fields.")

# Login
elif choice == "Login":
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if authenticate(username, password):
            st.session_state.is_logged_in = True
            st.session_state.current_user = username
            st.success(f"✅ Welcome, {username}!")
      
        else:
            st.error("❌ Invalid username or password.")

# Logout
elif choice == "Logout":
    if(st.session_state.is_logged_in):
        st.session_state.is_logged_in = False
        st.session_state.current_user = None
        st.success("✅ Logged out successfully.")
    else:
        st.warning("🔐 You have already logged out.")

# Store Data
elif choice == "Store Data":
    if not st.session_state.is_logged_in:
        st.warning("🔐 Please log in first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        title = st.text_input("Enter title for this data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Enter passkey for this data", type="password")

        if st.button("Encrypt & Store"):
            if title and data and passkey:
                hashed_passkey = hash_passkey(passkey)
                encrypted = encrypt_data(data)
                if st.session_state.current_user not in stored_data:
                    stored_data[st.session_state.current_user] = []
                stored_data[st.session_state.current_user].append({
                    "title": title,
                    "encrypted_text": encrypted,
                    "passkey": hashed_passkey
                })
                save_json(stored_data, DATA_FILE)
                st.success("✅ Data stored securely!")
            else:
                st.warning("Please fill all fields.")
    
# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.is_logged_in:
        st.warning("🔐 Please log in first.")
    elif is_locked_out():
        pass
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_entries = stored_data.get(st.session_state.current_user, [])
        if not user_entries:
            st.info("ℹ️ No stored data found.")
        else:
            for i, entry in enumerate(user_entries):
                with st.expander(f"{entry.get('title', f'Entry {i+1}')}"):
                    st.code(entry["encrypted_text"])
                    passkey = st.text_input(f"Passkey for entry {i+1}", type="password", key=f"pass_{i}")
                    if st.button(f"Decrypt {i+1}"):
                        if hash_passkey(passkey) == entry["passkey"]:
                            decrypted = decrypt_data(entry["encrypted_text"])
                            st.success(f"✅ Decrypted Data: {decrypted}")
                            st.session_state.failed_attempts = 0
                        else:
                            st.session_state.failed_attempts += 1
                            st.error(f"❌ Incorrect passkey! Attempts left: {MAX_ATTEMPTS - st.session_state.failed_attempts}")
                            if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                                st.session_state.lockout_time = datetime.now()
                                st.warning("🔒 Too many failed attempts. Temporarily locked out.")
                                st.rerun()
