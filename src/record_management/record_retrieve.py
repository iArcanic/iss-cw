# record_retrieve.py

from src.decryption import aes_data_decrypt
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
            record["data"] = aes_data_decrypt(aes_key, record["data"])
            records_list.append(record)

    return records_list


