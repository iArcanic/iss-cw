import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# AES data encryption operation
def aes_encrypt(key, data):
    # Check whether the AES key is of the required length
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes long for AES-256")

    # Create a new initialisation vector of 16 characters
    iv = os.urandom(16)

    # Create a new cipher with the AES key and initialisation vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Make a new encrypter with that cipher to encrypt the data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Concatenate the IV and ciphertext to form the final ciphertext
    return iv + ciphertext
