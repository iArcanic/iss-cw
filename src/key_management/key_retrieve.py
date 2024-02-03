# key_retrieve.py

import json

HSM_DB = "data/hsm.json"

def retrieve_key(user_id):
    try:
        with open(HSM_DB) as f:
            key_entries = [json.loads(line) for line in f]

            for entry in key_entries:
                if entry["user_id"] == user_id:
                    key = bytes.fromhex(entry["key"])
                    return key

            print(f"Key for user {user_id} not found in HSM!")
            return None

    except FileNotFoundError:
        print(f"HSM database {HSM_DB} not found!")
        return None