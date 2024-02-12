# key_retrieve.py

from src.data_manager import *

# Hardware Security Module (HSM) for AES keys simulation
HSM_DB = "data/hsm.json"


def retrieve_key(user_id):

    # Read all key entries from HSM
    key_entries = data_read(HSM_DB)

    for entry in key_entries["aes_keys"]:
        # Get the correct record
        if entry["user_id"] == user_id:
            # Return AES key from hex into a usable format
            return bytes.fromhex(entry["key"])

    print(f"key_retrieve.retrieve_key -> Key for user {user_id} not found in {HSM_DB}!")
    return None
