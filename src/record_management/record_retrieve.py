# record_retrieve.py

from src.decryption import aes_data_decrypt
from src.key_management.key_retrieve import *
from src.role_check import *

# Records database simulation
RECORDS_DB = "data/records_db.json"


# Decorator executed each time function is run
@role_check_decorator
# Get all records based on record owner_id, patient_id, and the permission of user performing this operation
def record_retrieve(owner_id, patient_id, permission):
    # List to capture all found records
    records_list = []

    # Get all record entries
    records_data = data_read(RECORDS_DB)

    # Get relevant AES key based on record owner_id
    aes_key = retrieve_key(owner_id)

    for record in records_data["records"]:
        # Get the correct record based on the record owner_id and patient_id
        if record["owner_id"] == owner_id and record["meta_data"]["patient_id"] == patient_id:

            # Use AES key to perform AES decryption on data
            # Overwrite encrypted data with the decrypted plaintext
            record["data"] = aes_data_decrypt(aes_key, record["data"])

            # Add all found and modified records to list
            records_list.append(record)

    return records_list


# Retrieve record by record_id
def record_retrieve_by_id(record_id, user_id):
    # Get all record entries
    records_data = data_read(RECORDS_DB)

    # Filter records by record_id
    record = list(filter(lambda x: x["record_id"] == record_id, records_data["records"]))[0]

    # Get record that has individual access for given user_id
    if user_id in record["individual_access"]:
        # Get record owner's AES key
        aes_key = retrieve_key(record["owner_id"])

        # Use AES key to perform AES decryption on data
        # Overwrite encrypted data with the decrypted plaintext
        record["data"] = aes_data_decrypt(aes_key, record["data"])

        return record
    else:
        # Raise error if the wrong user tried to access the record
        raise PermissionError(
            f"record_retrieve.record_retrieve_by_id -> User with ID {user_id} does not have required permissions for "
            f"this operation."
        )
