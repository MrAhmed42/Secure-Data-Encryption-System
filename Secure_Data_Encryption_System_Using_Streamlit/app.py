import streamlit as st
import hashlib
import time
import base64
import uuid
from cryptography.fernet import Fernet

# === SESSION STATE INITIALIZATION ===
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0
if 'last_login_time' not in st.session_state:
    st.session_state.last_login_time = 0

# === CONSTANTS ===
LOCKOUT_THRESHOLD = 3
LOCKOUT_TIME = 10  # seconds
SESSION_TIMEOUT = 300  # seconds
ADMIN_PASSWORD_HASH = hashlib.sha256("hello123".encode()).hexdigest()

# === HELPER FUNCTIONS ===
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    return base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passkey"] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def generate_data_id():
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page
    st.rerun()

# === UI START ===
st.title("🔒 Secure Data Encryption System")

# Check for session timeout
if st.session_state.last_login_time > 0 and time.time() - st.session_state.last_login_time > SESSION_TIMEOUT:
    st.warning("⏰ Session expired. Please login again.")
    st.session_state.current_page = "Login"
    st.session_state.failed_attempts = LOCKOUT_THRESHOLD
    st.rerun()

# Build dynamic menu
menu = ["Home", "Store Data", "Retrieve Data"]
if st.session_state.failed_attempts >= LOCKOUT_THRESHOLD:
    menu = ["Login"]
choice = st.sidebar.selectbox("Select a page", menu, index=0)
st.session_state.current_page = choice

# Lockout redirection
if st.session_state.failed_attempts >= LOCKOUT_THRESHOLD and st.session_state.current_page != "Login":
    st.warning("Too many failed attempts. Redirecting to Login page.")
    st.session_state.current_page = "Login"
    st.rerun()

# === PAGE: HOME ===
if st.session_state.current_page == "Home":
    st.subheader("Welcome to the Secure Data Encryption System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")

    st.info(f"🧾 Total stored data entries: {len(st.session_state.stored_data)}")

# === PAGE: STORE DATA ===
elif st.session_state.current_page == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a passkey to encrypt the data:", type="password")
    confirm_passkey = st.text_input("Confirm passkey:", type="password")

    if st.button("Encrypt and Store Data"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("❌ Passkeys do not match. Please try again.")
            else:
                data_id = generate_data_id()
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success(f"✅ Data stored successfully with ID: `{data_id}`")
                st.info("⚠️ Save this Data ID to retrieve your data later.")
        else:
            st.error("⚠️ Please fill in all fields.")

# === PAGE: RETRIEVE DATA ===
elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    attempts_remaining = LOCKOUT_THRESHOLD - st.session_state.failed_attempts
    st.info(f"❗ Attempts remaining: {attempts_remaining}")

    data_id = st.text_input("Enter the Data ID:")
    passkey = st.text_input("Enter the passkey to decrypt the data:", type="password")

    if st.button("Decrypt Data"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                if decrypted_text:
                    st.success(f"✅ Decrypted Data:\n\n```\n{decrypted_text}\n```")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_remaining - 1}")
            else:
                st.error("❌ Invalid Data ID. Please check and try again.")
        else:
            st.error("⚠️ Both fields are required!")

        if st.session_state.failed_attempts >= LOCKOUT_THRESHOLD:
            st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
            st.session_state.current_page = "Login"
            st.rerun()

# === PAGE: LOGIN ===
elif st.session_state.current_page == "Login":
    st.subheader("🔑 Reauthorization Required")

    if time.time() - st.session_state.last_attempt_time < LOCKOUT_TIME:
        remaining_time = int(LOCKOUT_TIME - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"⏳ Please wait {remaining_time} seconds before trying again.")
    else:
        login_passkey = st.text_input("Enter the admin password:", type="password")

        if st.button("Login"):
            if hash_passkey(login_passkey) == ADMIN_PASSWORD_HASH:
                reset_failed_attempts()
                st.session_state.last_login_time = time.time()
                st.success("✅ Reauthorized successfully!")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("❌ Incorrect password!")

st.markdown("---")
