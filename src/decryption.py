# decryption.py
import base64

from src.encryption import *


# AES data decryption operation
def aes_data_decrypt(aes_key, data):
    # Base64 decode the encrypted data
    ciphertext = base64.b64decode(data)
    print(f"record_store.record_store -> Encrypted data at rest {ciphertext}")

    # Splice the initialisation vector from the cipher text
    iv = ciphertext[:16]

    # Splice the actual encrypted data content from the ciphertext
    actual_ciphertext = ciphertext[16:]

    # Check whether the AES key is of the required length
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes long for AES-256")

    # Create a new AES cipher using the AES key and IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())

    # Make a new decrypter with that cipher to decrypt the data
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Decode the plaintext to string from bytes
    plaintext = decrypted_data
    return plaintext.decode()
