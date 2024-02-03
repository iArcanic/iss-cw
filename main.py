# main.py

from src.encryption import *
from src.decryption import *
from src.authentication.login import *
from src.authentication.register import *
from src.authentication.sso import *
from src.key_management.key_gen import *
from src.key_management.key_store import *
from src.key_management.key_retrieve import *
from src.record_management.record_store import *
from datetime import datetime

if __name__ == '__main__':

    # register_user("john_doe", "mySecurePassword", "07123456789")
    user_id = "6967dcf0-fd7e-47ea-90a5-c10265650173"

    # single_sign_on("john_doe")

    # aes_key = generate_aes_key()

    # store_key_in_hsm("6967dcf0-fd7e-47ea-90a5-c10265650173", aes_key)

    # user_retrieved_key = retrieve_key("6967dcf0-fd7e-47ea-90a5-c10265650173")
    # print(user_retrieved_key.hex())

    med_records_data = {
        "blood_pressure": 120,
        "blood_glucose": 120,
        "blood_sugar": 120
    }

    record_store(
        owner_id=user_id,
        data=med_records_data,
        meta_data={
            "patient_id": "0da97ef6-3af0-423f-884c-40cf23184a50",
            "data_type": "MEDICAL_RECORD",
            "timestamp": datetime.utcnow().isoformat()
        },
        permission="MEDICAL_RECORD_EDIT"
    )

    # ciphertext = aes_encrypt(aes_retrieved_key, plaintext_data.encode())
    # print("Encrypted Data:", ciphertext.hex())

    # decrypted_data = aes_decrypt(aes_retrieved_key, ciphertext[:16], ciphertext[16:])
    # print("Decrypted Data:", decrypted_data.decode())