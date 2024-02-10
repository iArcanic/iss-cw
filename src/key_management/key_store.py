# key_store.py
import base64

from src.decryption import aes_data_decrypt
from src.encryption import aes_encrypt
from src.key_management.key_gen import generate_aes_key
from src.key_management.key_retrieve import *

HSM_DB = "data/hsm.json"
RECORDS_DB = "data/records_db.json"


def store_aes_key(user_id, key):
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


# This has to be highly transactional.
# For any failures, old key should be rolled back, including data encryption and decryption
def expire_aes_key(user_id):
    records_data = data_read(RECORDS_DB)

    old_aes_key = retrieve_key(user_id)
    new_aes_key = generate_aes_key()
    store_aes_key(user_id, new_aes_key)

    for record in records_data["records"]:
        if record["owner_id"] == user_id:
            record["data"] = aes_data_decrypt(old_aes_key, record["data"])

            ciphertext = aes_encrypt(new_aes_key, record["data"].encode())
            serialized_ciphertext = base64.b64encode(ciphertext).decode()
            record["data"] = serialized_ciphertext

    data_store(RECORDS_DB, records_data)
