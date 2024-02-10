# record_retrieve.py

from src.role_check import *
from src.key_management.key_retrieve import *
from src.decryption import *
import base64

RECORDS_DB = "data/records_db.json"


@role_check_decorator
def record_retrieve(owner_id, patient_id, permission):
    records_list = []
    records_data = data_read(RECORDS_DB)

    aes_key = retrieve_key(owner_id)

    for record in records_data["records"]:
        if record["owner_id"] == owner_id and record["meta_data"]["patient_id"] == patient_id:
            print(f"AES Key: {aes_key}")
            print(f"AES Key Hex: {aes_key.hex()}")

            serialized_ciphertext = record["data"]
            print(f"Serialized ciphertext: {serialized_ciphertext}")

            ciphertext = base64.b64decode(serialized_ciphertext)
            print(f"Ciphertext: {ciphertext}")

            iv = ciphertext[:16]
            print(f"IV: {iv}")

            actual_ciphertext = ciphertext[16:]
            print(f"Actual ciphertext: {actual_ciphertext}")

            plaintext = aes_decrypt(aes_key, iv, actual_ciphertext)
            print(f"Plaintext: {plaintext}")

            record["data"] = plaintext
            records_list.append(record)

    return records_list
