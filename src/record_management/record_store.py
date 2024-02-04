# record_store.py

import json
import base64
from datetime import datetime
from src.key_management.key_retrieve import retrieve_key
from src.encryption import *
from src.role_check import *
from src.data_manager import *

RECORDS_DB = "data/records_db.json"

@role_check_decorator
def record_store(owner_id, data, meta_data, permission):
    key = retrieve_key(owner_id)

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

    data_store(RECORDS_DB, {"owner_id": owner_id, "data": serialized_ciphertext, "meta_data": meta_data})