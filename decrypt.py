import argparse
from key_management import generate_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def decrypt_aes(encrypted_data: str, password: str):
    """Decrypts AES encrypted text."""
    salt = bytes.fromhex(encrypted_data[:32])  
    iv = bytes.fromhex(encrypted_data[32:64])  
    ciphertext = bytes.fromhex(encrypted_data[64:])  

    key, _ = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = plaintext_padded[-1]  
    plaintext = plaintext_padded[:-padding_length]  
    return plaintext.decode()

def decrypt_rsa(encrypted_hex: str, private_key_path="private_key.pem"):
    """Decrypts an RSA encrypted message."""
    encrypted = bytes.fromhex(encrypted_hex)

    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt a message.")
    parser.add_argument("encrypted_message", help="Encrypted message (hex)")
    parser.add_argument("--method", choices=["aes", "rsa"], required=True, help="Decryption method (AES or RSA)")
    parser.add_argument("--password", help="Password for AES decryption (required for AES)", default=None)

    args = parser.parse_args()

    if args.method == "aes":
        if not args.password:
            print("Error: AES decryption requires a password.")
        else:
            decrypted_message = decrypt_aes(args.encrypted_message, args.password)
            print(f"Decrypted (AES): {decrypted_message}")

    elif args.method == "rsa":
        decrypted_message = decrypt_rsa(args.encrypted_message)
        print(f"Decrypted (RSA): {decrypted_message}")
