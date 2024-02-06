# key_retrieve.py

from src.data_manager import *

HSM_DB = "data/hsm.json"


def retrieve_key(user_id):
    key_entries = data_read(HSM_DB)

    for entry in key_entries["aes_keys"]:
        if entry["user_id"] == user_id:
            return bytes.fromhex(entry["key"])

    print(f"Key for user {user_id} not found in HSM!")
    return None
