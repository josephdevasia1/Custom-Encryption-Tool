# Custom Encryption Tool

## Overview
This is a hybrid encryption tool that supports both AES and RSA encryption. It provides a graphical user interface (GUI) for user-friendly interaction and command-line functionality for advanced users.

## Features
- **AES Encryption** (Symmetric)
- **RSA Encryption** (Asymmetric)
- **Hybrid Encryption** (AES key encrypted with RSA)
- **Graphical User Interface (GUI)** for easy input
- **Command-line Support** for advanced usage
- **File Encryption Support**

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/CustomEncryptionTool.git
   cd CustomEncryptionTool
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage
### GUI Mode
Run the standard GUI application:
```sh
python gui_encryptor.py
```
Run the hybrid encryption GUI:
```sh
python hybrid.py
```
Alternatively, if using the pre-built executables in the `dist` folder:
```sh
./dist/gui_encryptor.exe
./dist/hybrid.exe
```
Enter your message, select the encryption method (AES/RSA/Hybrid), and provide a password if needed.

### Command-line Mode
#### AES Encryption
```sh
python encrypt.py "your_message" --method aes --password yourpassword
```
#### RSA Encryption
```sh
python encrypt.py "your_message" --method rsa
```
#### Hybrid Encryption (AES + RSA)
```sh
python encrypt.py "your_message" --method hybrid --password yourpassword
```
#### Decryption
```sh
python decrypt.py "encrypted_message" --method aes --password yourpassword
python decrypt.py "encrypted_message" --method rsa
python decrypt.py "encrypted_message" --method hybrid --password yourpassword
```

## GUI Preview
The GUI allows users to input a message, choose encryption methods, and generate encrypted output easily.

## Security Considerations
- Use strong passwords for AES encryption.
- Keep your RSA private key secure.
- Do not share encrypted data without a secure key exchange.

## Future Improvements
- Implement key exchange using Diffie-Hellman.
- Support more encryption algorithms.
- Add file encryption for different formats.

## License
MIT License

---

This tool is designed for educational purposes and should be used responsibly. 🚀

