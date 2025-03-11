import hashlib
import os
import base64

def generate_key(password: str, salt: bytes = None):
    """Generates a 256-bit AES key from a password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random 16-byte salt

    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)  # 256-bit key

    return key, salt  # Ensure key and salt are returned

if __name__ == "__main__":
    password = input("Enter password: ").strip()
    aes_key, salt = generate_key(password)  # Ensure key and salt are stored in variables

    print(f"Generated AES Key (Hex): {aes_key.hex()}")  # Convert to hex
    print(f"Generated AES Key (Base64): {base64.b64encode(aes_key).decode()}")  # Convert to base64
    print(f"Salt (Hex): {salt.hex()}")  # Print the salt for reference
