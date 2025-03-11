import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os

# AES Encryption
def encrypt_aes(plain_text, password):
    key = password.ljust(32)[:32].encode()  # Ensure key is 32 bytes
    iv = os.urandom(16)  # Generate random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    padded_text = plain_text.ljust(16 * ((len(plain_text) // 16) + 1))  # Pad manually
    encrypted_text = encryptor.update(padded_text.encode()) + encryptor.finalize()
    
    return base64.b64encode(iv + encrypted_text).decode()

# AES Decryption
def decrypt_aes(encrypted_text, password):
    try:
        key = password.ljust(32)[:32].encode()  # Ensure key is 32 bytes
        data = base64.b64decode(encrypted_text)
        iv, encrypted_data = data[:16], data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return decrypted_text.decode().strip()
    except Exception as e:
        return f"Error: {e}"

# RSA Key Generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# RSA Encryption
def encrypt_rsa(plain_text):
    encrypted = public_key.encrypt(
        plain_text.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode()

# RSA Decryption
def decrypt_rsa(encrypted_text):
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_text),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return decrypted.decode()
    except Exception as e:
        return f"Error: {e}"

# GUI Setup
def encrypt_message():
    message = entry_message.get()
    password = entry_password.get()
    method = encryption_method.get()

    if not message:
        messagebox.showerror("Error", "Please enter a message to encrypt!")
        return

    if method == "AES":
        if not password:
            messagebox.showerror("Error", "AES encryption requires a password!")
            return
        encrypted = encrypt_aes(message, password)
    else:
        encrypted = encrypt_rsa(message)

    entry_result.delete(0, tk.END)
    entry_result.insert(0, encrypted)

def decrypt_message():
    encrypted_message = entry_result.get()
    password = entry_password.get()
    method = encryption_method.get()

    if not encrypted_message:
        messagebox.showerror("Error", "Please enter an encrypted message!")
        return

    if method == "AES":
        if not password:
            messagebox.showerror("Error", "AES decryption requires a password!")
            return
        decrypted = decrypt_aes(encrypted_message, password)
    else:
        decrypted = decrypt_rsa(encrypted_message)

    messagebox.showinfo("Decryption Result", f"Decrypted Message: {decrypted}")

# Creating the GUI Window
root = tk.Tk()
root.title("Custom Encryption Tool")
root.geometry("500x400")

# Input Fields
tk.Label(root, text="Enter Message:").pack()
entry_message = tk.Entry(root, width=50)
entry_message.pack()

tk.Label(root, text="Enter Password (AES Only):").pack()
entry_password = tk.Entry(root, width=50, show="*")  # Hide password
entry_password.pack()

# Dropdown for Encryption Method
encryption_method = tk.StringVar(value="AES")
tk.Label(root, text="Choose Encryption Method:").pack()
tk.OptionMenu(root, encryption_method, "AES", "RSA").pack()

# Encrypt & Decrypt Buttons
btn_encrypt = tk.Button(root, text="Encrypt", command=encrypt_message)
btn_encrypt.pack(pady=5)

btn_decrypt = tk.Button(root, text="Decrypt", command=decrypt_message)
btn_decrypt.pack(pady=5)

# Output Field
tk.Label(root, text="Encrypted / Decrypted Output:").pack()
entry_result = tk.Entry(root, width=50)
entry_result.pack()

# Run the GUI
root.mainloop()
