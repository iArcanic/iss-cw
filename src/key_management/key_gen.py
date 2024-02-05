# key_gen.py

import os


def generate_aes_key():
    key = os.urandom(32)
    return key
