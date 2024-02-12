# key_store.py
import base64

from src.decryption import aes_data_decrypt
from src.encryption import aes_encrypt
from src.key_management.key_gen import generate_aes_key
from src.key_management.key_retrieve import *

# Hardware Security Module (HSM) for AES keys simulation
HSM_DB = "data/hsm.json"

# Records database simulation
RECORDS_DB = "data/records_db.json"


def store_aes_key(user_id, key):
    try:
        with open(HSM_DB, 'r') as file:
            # Read all key entries from HSM
            json_data = json.load(file)
    except FileNotFoundError:
        # If file is not found then make an empty aes_keys JSON collection
        json_data = {"aes_keys": []}

    for entry in json_data["aes_keys"]:
        if entry["user_id"] == user_id:
            # Store AES key as hex in database
            entry["key"] = key.hex()
            break
    else:
        # If user_id not found, insert a new entry using the given AES key
        json_data["aes_keys"].append({"user_id": user_id, "key": key.hex()})

    with open(HSM_DB, 'w') as file:
        json.dump(json_data, file, indent=2)


# This has to be highly transactional.
# For any failures, old key should be rolled back, including data encryption and decryption
def expire_aes_key(user_id):

    # Read all record entries from Records database
    records_data = data_read(RECORDS_DB)

    # Get AES old key
    old_aes_key = retrieve_key(user_id)

    # Make a new AES key
    new_aes_key = generate_aes_key()

    # Store new key under the given user_id
    store_aes_key(user_id, new_aes_key)

    for record in records_data["records"]:
        # Get the correct record
        if record["owner_id"] == user_id:
            # Decrypt the data of that record with the old AES key
            record["data"] = aes_data_decrypt(old_aes_key, record["data"])

            # Encrypt the data of that record with the new key
            ciphertext = aes_encrypt(new_aes_key, record["data"].encode())

            # Serialise the ciphertext so it can be stored as JSON
            serialized_ciphertext = base64.b64encode(ciphertext).decode()

            # Overwrite the data of that record with the new serialised ciphertext
            record["data"] = serialized_ciphertext

    # Write to Records database
    data_store(RECORDS_DB, records_data)
