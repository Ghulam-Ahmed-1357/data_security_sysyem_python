from cryptography.fernet import Fernet

key = Fernet.generate_key()
with open("secret.key", "wb") as f:
    f.write(key)

print("✅ secret.key file created successfully.")