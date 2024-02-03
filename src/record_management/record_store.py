# record_store.py

import json
import base64
from datetime import datetime
from src.key_management.key_retrieve import retrieve_key
from src.encryption import *
from src.role_check import *

RECORDS_DB = "data/records_db.json"

@role_check_decorator
def record_store(user_id, data, record_type, meta_data, action="store"):
    key = retrieve_key(user_id)

    # Ensure 'data' is a dictionary representing JSON data
    if not isinstance(data, dict):
        print("Error: 'data' must be a dictionary representing JSON data.")
        return

    # Convert the dictionary to a JSON-formatted string
    json_data = json.dumps(data, indent=2)

    # Encrypt the JSON-formatted data
    ciphertext = aes_encrypt(key, json_data.encode())

    # Convert the ciphertext to a JSON-serializable format (Base64-encoded string)
    serialized_ciphertext = base64.b64encode(ciphertext).decode()

    try:
        with open(RECORDS_DB, "w") as db_file:
            json.dump({"user_id": user_id, "data": serialized_ciphertext, "record_type": record_type, "meta_data": meta_data}, db_file, indent=2)

    except FileNotFoundError:
        print(f"MedRecords database {RECORDS_DB} not found!")
        return