import argparse
from key_management import generate_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def encrypt_aes(plaintext: str, password: str):
    """Encrypts text using AES-256."""
    key, salt = generate_key(password)  # Generates a valid 32-byte key
    iv = os.urandom(16)  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + chr(padding_length) * padding_length

    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return salt.hex() + iv.hex() + ciphertext.hex()


def encrypt_rsa(message: str, public_key_path="public_key.pem"):
    """Encrypts text using RSA public key."""
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted.hex()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt a message.")
    parser.add_argument("message", help="Message to encrypt")
    parser.add_argument("--method", choices=["aes", "rsa"], required=True, help="Encryption method (AES or RSA)")
    parser.add_argument("--password", help="Password for AES encryption (required for AES)", default=None)

    args = parser.parse_args()

    if args.method == "aes":
        if not args.password:
            print("Error: AES encryption requires a password.")
        else:
            encrypted_message = encrypt_aes(args.message, args.password)
            print(f"Encrypted (AES): {encrypted_message}")
    
    elif args.method == "rsa":
        encrypted_message = encrypt_rsa(args.message)
        print(f"Encrypted (RSA): {encrypted_message}")
