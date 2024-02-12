from datetime import datetime
from unittest.mock import patch

from src.key_management.rsa_key_manager import rsa_encrypt
from src.record_management.record_store import record_store
from tests.utils.test_utils import *


# Patches to automate inputs when program prompts user for it
@patch('builtins.input', return_value="123456")
@patch('src.authentication.register.generate_2fa_code')
@patch('src.authentication.login.generate_2fa_code')
def test_role_check_workflow(mock_generate_login_2fa_code, mock_generate_register_2fa_code, mock_input):
    # Perform new user register and login in one go
    public_key, user_id = register_user_and_login(mock_generate_login_2fa_code, mock_generate_register_2fa_code)

    # Create and store a new AES key for the new user
    generate_and_store_aes_key(user_id)

    # Write to the User roles database a new user with a new role
    # The role this time is a lesser privileged role
    role = "receptionist"
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

    try:
        print("User attempting to store record in database...")
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
        # Inform the assessor that we are expecting an error, since we gave the wrong role to the user
        print(f"User's {role} role does not have the necessary permissions to perform this operation.")
    except PermissionError as e:
        # Check whether the error received is the same error as in the role_check_decorator
        assert str(e) == (f"role_check.role_check_decorator -> User with ID {user_id} does not have required "
                          f"permissions for this operation.")
        print(f"PermissionError, {e}, raised as expected. User does not have the required role.")
    else:
        # Otherwise fail the test since the error did not arise
        assert False, "Expected PermissionError was not raised."
