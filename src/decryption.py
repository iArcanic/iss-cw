# decryption.py
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.encryption import *


def aes_data_decrypt(aes_key, data):
    ciphertext = base64.b64decode(data)
    print(f"record_store.record_store -> Encrypted data at rest {ciphertext}")
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes long for AES-256")
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
    plaintext = decrypted_data
    return plaintext.decode()
