# record_store.py

import base64
import uuid

from src.decrypt_data import *
from src.encryption import *
from src.key_management.key_retrieve import retrieve_key
from src.role_check import *

RECORDS_DB = "data/records_db.json"


@rsa_decrypt_data_decorator
@role_check_decorator
def record_store(owner_id, data, meta_data, permission, decrypted_data, individual_access=None):
    if individual_access is None:
        individual_access = []
    print(f"record_store.record_store -> Data received encrypted: {data}")
    key = retrieve_key(owner_id)

    # Decrypt data from data transmission
    json_data = json.dumps(decrypted_data, indent=2)

    # Encrypt the JSON-formatted data at rest
    ciphertext = aes_encrypt(key, json_data.encode())

    # Convert the ciphertext to a JSON-serializable format (Base64-encoded string)
    serialized_ciphertext = base64.b64encode(ciphertext).decode()

    try:
        with open(RECORDS_DB, 'r') as file:
            json_data = json.load(file)
    except FileNotFoundError:
        json_data = {"records": []}

    try:
        with open(RECORDS_DB, 'w') as file:
            record_id = str(uuid.uuid4())

            json_data["records"].append(
                {"record_id": record_id, "owner_id": owner_id, "data": serialized_ciphertext,
                 "meta_data": meta_data, "individual_access": individual_access})
            json.dump(json_data, file, indent=2)

            return record_id
    except FileNotFoundError:
        print(f"record_store.record_store -> {RECORDS_DB} not found.")
