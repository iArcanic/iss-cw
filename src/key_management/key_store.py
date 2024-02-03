# key_store.py

import json

HSM_DB = "data/hsm.json"

def store_key_in_hsm(user_id, key):
    # Make new key entry
    key_entry = {
        "user_id": user_id,
        "key": key.hex()
    }

    try:
        # Try to open the existing database file
        with open(HSM_DB, "r") as f:
            existing_entries = [json.loads(line) for line in f]

        # Check if user_id already exists in the database
        for entry in existing_entries:
            if entry["user_id"] == user_id:
                print(f"User with ID '{user_id}' already has a key stored. Skipping duplicate entry.")
                return False

        # If user_id doesn't exist, add the new entry
        with open(HSM_DB, "a") as f:
            json.dump(key_entry, f)
            f.write('\n')  # Add a newline to separate entries
        return True

    except FileNotFoundError:
        print("HSM database not found.")
        return False