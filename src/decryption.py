# decryption.py
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from src.encryption import *
from src.key_management.key_retrieve import retrieve_key


def aes_decrypt(key, iv, ciphertext):
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes long for AES-256")
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data


# sample_data = {
#     "message": "Hello World!"
# }
#
# public_key = """-----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0JNEoNNyo4U+wgla0EPJ
# YVQ8p04cc7rLLvxUSI3ACyBqAcCRJETEjQOUefr9RFQwqnN16OTKlGVe40hZUal8
# c9xcDH5uOcxfzt+AflAG4cFJcsraJJhS9nHKVORA/g5Gkxl8ZxgWQ/pLz6z2gjHk
# w9ZxnxJab1ImfIA8WeNbh5BE0zHpvSTcCi3kAgWxrK3ulHKqhiTv6Sns90dN93Uy
# 20CfzOFC0Ggx6CaLGAVNW9MpvEXjAVw2/lRvFEA/52Ro8m1lfUDsK5g7g2xnN4Lr
# Z0WM3EAlQqdL02oG/It9Iz+g/vUvm2H/SfCefdfPOG4MWf/kcUg/fsbMWjXabP+1
# LQIDAQAB
# -----END PUBLIC KEY-----"""
#
# # user_id = "6967dcf0-fd7e-47ea-90a5-c10265650173"
#
# aes_key = "87e01682824a9ec4868fb1e672e0ebefa00ee310bbb8ae9e225d4e65b6c4e6a4"
#
# print("Encrypting message...")
#
# ciphertext = aes_encrypt(bytes.fromhex(aes_key), json.dumps(sample_data).encode())
# print(f"Ciphertext: {ciphertext}")
#
# serialized_ciphertext = base64.b64encode(ciphertext).decode()
# print(f"Serialized ciphertext: {serialized_ciphertext}")
#
# print("Decrypting message...")
#
# ciphertext = base64.b64decode(serialized_ciphertext)
# print(f"Ciphertext: {ciphertext}")
#
# iv = ciphertext[:16]
# print(f"IV: {iv}")
# actual_ciphertext = ciphertext[16:]
# print(f"Actual ciphertext: {actual_ciphertext}")
# print(f"Plaintext: {aes_decrypt(bytes.fromhex(aes_key), iv, actual_ciphertext)}")
