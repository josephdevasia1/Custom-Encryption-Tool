from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    """Generates an RSA key pair and saves them as private_key.pem and public_key.pem."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048  # 2048-bit key for security
    )
    
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("✅ RSA Key Pair Generated Successfully!")
    print("🔒 Private Key: private_key.pem")
    print("🔑 Public Key: public_key.pem")

if __name__ == "__main__":
    generate_rsa_keys()
