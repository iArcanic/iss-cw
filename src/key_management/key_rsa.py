# key_rsa.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_data(data, private_key):
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(data, signature, public_key):
    public_key.verify(
        base64.b64decode(signature),
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# # Sample data
# data = "Patient records"

# # Use asymmetric keys
# private_key, public_key = generate_key_pair()

# # Sign data
# signature = sign_data(data, private_key)
# print(f"Signature:\n{signature}\n")

# # Verify after transfer
# verify_signature(data, signature, public_key)
# print("Signature verified successfully.")
