import os
import base64
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# RSA Key Paths
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

# Generate RSA keys if not exist
def generate_rsa_keys():
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

# AES Encryption
def encrypt_aes(plain_text, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_text = plain_text.ljust(16 * ((len(plain_text) // 16) + 1)).encode()
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_text).decode()

# RSA Encryption for AES key
def encrypt_aes_key(aes_key):
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted_key).decode()

# AES Decryption
def decrypt_aes(encrypted_text, aes_key):
    try:
        data = base64.b64decode(encrypted_text)
        iv, encrypted_data = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_text.decode().strip()
    except Exception as e:
        return f"Error: {e}"

# RSA Decryption for AES key
def decrypt_aes_key(encrypted_key):
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    decrypted_key = private_key.decrypt(
        base64.b64decode(encrypted_key),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_key

# Hybrid Encryption
def hybrid_encrypt():
    message = message_entry.get()
    if not message:
        messagebox.showerror("Error", "Please enter a message.")
        return

    aes_key = os.urandom(32)
    encrypted_message = encrypt_aes(message, aes_key)
    encrypted_key = encrypt_aes_key(aes_key)

    encrypted_text_area.delete("1.0", tk.END)
    encrypted_text_area.insert(tk.END, f"Encrypted Message:\n{encrypted_message}\n\nEncrypted AES Key:\n{encrypted_key}")

# Hybrid Decryption
def hybrid_decrypt():
    encrypted_data = encrypted_text_area.get("1.0", tk.END).strip().split("\n\n")
    if len(encrypted_data) < 2:
        messagebox.showerror("Error", "Invalid encrypted data format.")
        return

    encrypted_message = encrypted_data[0].replace("Encrypted Message:\n", "").strip()
    encrypted_key = encrypted_data[1].replace("Encrypted AES Key:\n", "").strip()

    aes_key = decrypt_aes_key(encrypted_key)
    decrypted_message = decrypt_aes(encrypted_message, aes_key)

    decrypted_text_area.delete("1.0", tk.END)
    decrypted_text_area.insert(tk.END, f"Decrypted Message:\n{decrypted_message}")

# GUI
generate_rsa_keys()
root = tk.Tk()
root.title("Hybrid Encryption Tool (AES + RSA)")

# Input Section
tk.Label(root, text="Enter Message:").pack()
message_entry = tk.Entry(root, width=50)
message_entry.pack()

# Encryption Button
encrypt_button = tk.Button(root, text="Encrypt", command=hybrid_encrypt)
encrypt_button.pack()

# Encrypted Output Section
tk.Label(root, text="Encrypted Data:").pack()
encrypted_text_area = scrolledtext.ScrolledText(root, width=60, height=5)
encrypted_text_area.pack()

# Decryption Button
decrypt_button = tk.Button(root, text="Decrypt", command=hybrid_decrypt)
decrypt_button.pack()

# Decrypted Output Section
tk.Label(root, text="Decrypted Message:").pack()
decrypted_text_area = scrolledtext.ScrolledText(root, width=60, height=2)
decrypted_text_area.pack()

root.mainloop()
