# main.py

from datetime import datetime

from src.authentication.login import *
from src.key_management.key_store import expire_aes_key
from src.key_management.rsa_key_manager import *
from src.record_management.record_retrieve import *
from src.record_management.record_store import *

if __name__ == '__main__':
    # # register_user("john_doe1", "mySecurePassword", "07123456789")
    # user_id, public_key = login_user("john_doe", "mySecurePassword")
    # # print(f"Logged in as {user_id}")
    # print(f"Public key: {public_key}")
    #
    # # single_sign_on("john_doe")
    #
    # # aes_key = generate_aes_key()
    # # store_key_in_hsm(user_id, aes_key)
    #
    # user_retrieved_key = retrieve_key(user_id)
    # print(f"Retrieved user_id key: {user_retrieved_key}")
    # #
    # med_records_data = {
    #     "message": "Hello World!"
    # }
    # #
    # ciphertext = rsa_encrypt(str(med_records_data), public_key)
    # print(f"Ciphertext: {ciphertext}")
    # #
    # record_store(
    #     owner_id=user_id,
    #     data=ciphertext,
    #     meta_data={
    #         "patient_id": "0da97ef6-3af0-423f-884c-40cf23184a50",
    #         "data_type": "MEDICAL_RECORD",
    #         "timestamp": datetime.utcnow().isoformat()
    #     },
    #     permission="MEDICAL_RECORD_EDIT"
    # )
    #
    # record = record_retrieve(
    #     owner_id=user_id,
    #     patient_id="0da97ef6-3af0-423f-884c-40cf23184a50",
    #     permission="MEDICAL_RECORD_VIEW"
    # )
    #
    # print(f"Final record: {record}")

    expire_aes_key("82556c24-be71-4fcf-bd23-c9deddde26b9")
