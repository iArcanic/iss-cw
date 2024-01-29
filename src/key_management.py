# key_management.py

import json

HSM_DB = "hsm.json"

def store_keys_in_hsm(keys):
    key_entries = []

    for key_id, key in keys.items():
        key_entry = {
            "key_id": key_id,
            "key": key.hex()
        }
        key_entries.append(key_entry)

    with open(HSM_DB, "w") as f:
        json.dump(key_entries, f)

    return True

def retrieve_key(key_id):
    try:
        with open(HSM_DB) as f:
            key_entries = json.load(f)

            for entry in key_entries:
                if entry["key_id"] == key_id:
                    key = bytes.fromhex(entry["key"])
                    return key

            print(f"Key {key_id} not found in HSM!")
            return None

    except FileNotFoundError:
        print(f"HSM database {HSM_DB} not found!")
        return None