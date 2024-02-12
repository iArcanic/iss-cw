from datetime import datetime

from src.record_management.record_retrieve import *
from src.record_management.record_store import *
from tests.authentication_workflow_tests import *
from tests.utils.test_utils import *
from tests.utils.test_utils import assign_user_to_role, generate_and_store_aes_key, assert_record_retrieved_decrypted

# Users database simulation
USERS_DB = "data/user_db.json"

# User roles database simulation
USER_ROLES_DB = "data/user_roles_db.json"


# Patches to automate inputs when program prompts user for it
@patch('builtins.input', return_value="123456")
@patch('src.authentication.register.generate_2fa_code')
@patch('src.authentication.login.generate_2fa_code')
# Data transmission, including record store and retrieve, workflow test case
def test_data_transmission_workflow(mock_generate_login_2fa_code, mock_generate_register_2fa_code, mock_input):
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
        "blood_pressure": 120,
        "blood_glucose": 110
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

    # Perform record retrieve
    record = record_retrieve(
        owner_id=user_id,
        patient_id="0da97ef6-3af0-423f-884c-40cf23184a50",
        permission="MEDICAL_RECORD_VIEW"
    )

    # Check whether the record list has one record returned
    assert len(record) == 1
    print(f'Data decrypted to original: {str(record[0]["data"])}')

    # Check whether the record before encryption and after encryption are exactly the same
    assert_record_retrieved_decrypted(patient_record, record[0])

