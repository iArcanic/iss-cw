# record_store.py

import base64
import uuid

from src.decrypt_data import *
from src.encryption import *
from src.key_management.key_retrieve import retrieve_key
from src.role_check import *

# Records database simulation
RECORDS_DB = "data/records_db.json"


# Decorators executed each time function is run
@rsa_decrypt_data_decorator
@role_check_decorator
# Store a record based on record owner_id, data, meta-data, permission of user performing this operation,
# decrypted data from RSA data transmission, and individual access rights
def record_store(owner_id, data, meta_data, permission, decrypted_data, individual_access=None):
    # If individual_access parameter is not passed when function is called
    if individual_access is None:
        # Create empty collection to be stored in the JSON object
        individual_access = []
    print(f"record_store.record_store -> Data received encrypted: {data}")

    # Get AES key record owner
    key = retrieve_key(owner_id)

    # Decrypt data from data transmission
    json_data = json.dumps(decrypted_data, indent=2)

    # Encrypt the JSON-formatted data at rest
    ciphertext = aes_encrypt(key, json_data.encode())

    # Convert the ciphertext to a JSON-serializable format (Base64-encoded string)
    serialized_ciphertext = base64.b64encode(ciphertext).decode()

    try:
        with open(RECORDS_DB, 'r') as file:
            # Read all record entries from Records database
            json_data = json.load(file)
    except FileNotFoundError:
        # If file is not found then make an empty records JSON collection
        json_data = {"records": []}

    try:
        with open(RECORDS_DB, 'w') as file:

            # Make UUID dynamically for each new record
            record_id = str(uuid.uuid4())

            # Add to records JSON collection
            json_data["records"].append(
                {"record_id": record_id, "owner_id": owner_id, "data": serialized_ciphertext,
                 "meta_data": meta_data, "individual_access": individual_access})

            # Write to the Records database
            json.dump(json_data, file, indent=2)

            return record_id

    except FileNotFoundError:
        print(f"record_store.record_store -> {RECORDS_DB} not found.")
