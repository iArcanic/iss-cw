# record_retrieve.py

import base64

from src.decryption import *
from src.key_management.key_retrieve import *
from src.role_check import *

RECORDS_DB = "data/records_db.json"


@role_check_decorator
def record_retrieve(owner_id, patient_id, permission):
    records_list = []
    records_data = data_read(RECORDS_DB)

    aes_key = retrieve_key(owner_id)

    for record in records_data["records"]:
        if record["owner_id"] == owner_id and record["meta_data"]["patient_id"] == patient_id:
            serialized_ciphertext = record["data"]
            ciphertext = base64.b64decode(serialized_ciphertext)
            iv = ciphertext[:16]
            actual_ciphertext = ciphertext[16:]
            plaintext = aes_decrypt(aes_key, iv, actual_ciphertext)
            record["data"] = plaintext
            records_list.append(record)

    return records_list
