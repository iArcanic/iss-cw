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


def record_retrieve_by_id(record_id, user_id):
    records_data = data_read(RECORDS_DB)
    record = list(filter(lambda x: x["record_id"] == record_id, records_data["records"]))[0]
    if user_id in record["individual_access"]:
        aes_key = retrieve_key(record["owner_id"])
        record["data"] = aes_data_decrypt(aes_key, record["data"])
        return record
    else:
        raise PermissionError(
            f"record_retrieve.record_retrieve_by_id -> User with ID {user_id} does not have required permissions for "
            f"this operation."
        )
