# record_store.py

import json
import base64
from datetime import datetime
from src.key_management.key_retrieve import retrieve_key
from src.encryption import *
from src.role_check import *
from src.decrypt_data import *
from src.data_manager import *

RECORDS_DB = "data/records_db.json"


@decrypt_data_decorator
@role_check_decorator
def record_store(owner_id, data, meta_data, permission, decrypted_data):
    print(f"Decrypted data: {decrypted_data}")
    print(f"Owner ID: {owner_id}")

    key = retrieve_key(owner_id)

    # Decrypt data from data transmission
    json_data = json.dumps(decrypted_data, indent=2)

    # Encrypt the JSON-formatted data at rest
    ciphertext = aes_encrypt(key, json_data.encode())

    # Convert the ciphertext to a JSON-serializable format (Base64-encoded string)
    serialized_ciphertext = base64.b64encode(ciphertext).decode()

    data_store(RECORDS_DB, {"owner_id": owner_id, "data": serialized_ciphertext, "meta_data": meta_data})
