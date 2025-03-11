# Custom Encryption Tool
 
Custom Encryption Tool

Overview

This is a hybrid encryption tool that supports both AES and RSA encryption. It provides a graphical user interface (GUI) for user-friendly interaction and command-line functionality for advanced users.

Features

AES Encryption (Symmetric)

RSA Encryption (Asymmetric)

Hybrid Encryption (AES key encrypted with RSA)

Graphical User Interface (GUI) for easy input

Command-line Support for advanced usage

File Encryption Support

Installation

Clone the repository:

git clone https://github.com/yourusername/CustomEncryptionTool.git
cd CustomEncryptionTool

Install dependencies:

pip install -r requirements.txt

Usage

GUI Mode

Run the standard GUI application:

python gui_encryptor.py

Run the hybrid encryption GUI:

python hybrid.py

Alternatively, if using the pre-built executables in the dist folder:

./dist/gui_encryptor.exe
./dist/hybrid.exe

Enter your message, select the encryption method (AES/RSA/Hybrid), and provide a password if needed.

Command-line Mode

AES Encryption

python encrypt.py "your_message" --method aes --password yourpassword

RSA Encryption

python encrypt.py "your_message" --method rsa

Hybrid Encryption (AES + RSA)

python encrypt.py "your_message" --method hybrid --password yourpassword

Decryption

python decrypt.py "encrypted_message" --method aes --password yourpassword
python decrypt.py "encrypted_message" --method rsa
python decrypt.py "encrypted_message" --method hybrid --password yourpassword

GUI Preview

The GUI allows users to input a message, choose encryption methods, and generate encrypted output easily.

Security Considerations

Use strong passwords for AES encryption.

Keep your RSA private key secure.

Do not share encrypted data without a secure key exchange.

Future Improvements

Implement key exchange using Diffie-Hellman.

Support more encryption algorithms.

Add file encryption for different formats.

License

MIT License