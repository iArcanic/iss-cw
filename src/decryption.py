# decryption.py

from src.encryption import *


def aes_decrypt(key, iv, ciphertext):
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes long for AES-256")
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data
