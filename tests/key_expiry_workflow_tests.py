from datetime import datetime
from unittest.mock import patch

from src.key_management.key_store import *
from src.record_management.record_retrieve import *
from src.record_management.record_store import *
from tests.utils.test_utils import *


# Patches to automate inputs when program prompts user for it
@patch('builtins.input', return_value="123456")
@patch('src.authentication.register.generate_2fa_code')
@patch('src.authentication.login.generate_2fa_code')
def test_key_expiry_workflow(mock_generate_login_2fa_code, mock_generate_register_2fa_code, mock_input):
    # Perform new user register and login in one go
    public_key, user_id = register_user_and_login(mock_generate_login_2fa_code, mock_generate_register_2fa_code)

    # Create and store a new AES key for the new user
    generate_and_store_aes_key(user_id)

    # Write to the User roles database a new user with a new role
    role = "doctor"
    assign_user_to_role(user_id, role)
    print(f"User assigned the role of {role}.")

    # Sample record data
    patient_record = str({
        "blood_pressure": 200,
        "blood_glucose": 300
    })
    print(f'Raw patient_record: {str(patient_record)}')

    # Encrypt sample record data with new users user's public key
    encrypted_patient_record = rsa_encrypt(patient_record, public_key)

    # Perform record store
    record_store(
        owner_id=user_id,
        data=encrypted_patient_record,
        meta_data={
            "patient_id": "0da97ef6-3af0-423f-884c-40cf23184a50",
            "data_type": "MEDICAL_RECORD",
            "timestamp": datetime.utcnow().isoformat()
        },
        permission="MEDICAL_RECORD_EDIT"
    )

    # Retrieve that same record
    original_record = record_retrieve(
        owner_id=user_id,
        patient_id="0da97ef6-3af0-423f-884c-40cf23184a50",
        permission="MEDICAL_RECORD_VIEW"
    )

    print(f"Original record: {str(original_record)}")

    # Expire the AES key
    expire_aes_key(user_id)

    # Retrieve the same record again
    new_record = record_retrieve(
        owner_id=user_id,
        patient_id="0da97ef6-3af0-423f-884c-40cf23184a50",
        permission="MEDICAL_RECORD_VIEW"
    )

    print(f"New record: {str(new_record)}")

    # Check whether both the records match, despite key rotation
    assert new_record == original_record
