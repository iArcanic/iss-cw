# key_store.py

import json
from src.data_manager import *

HSM_DB = "data/hsm.json"


def store_key_in_hsm(user_id, key):
    try:
        with open(HSM_DB, 'r') as file:
            json_data = json.load(file)
    except FileNotFoundError:
        json_data = {"aes_keys": []}

    for entry in json_data["aes_keys"]:
        if entry["user_id"] == user_id:
            entry["key"] = key.hex()
            break
    else:
        # If user_id not found, insert a new entry
        json_data["aes_keys"].append({"user_id": user_id, "key": key.hex()})

    with open(HSM_DB, 'w') as file:
        json.dump(json_data, file, indent=2)
