from datetime import datetime
from unittest.mock import patch

from src.key_management.rsa_key_manager import rsa_encrypt
from src.record_management.record_store import record_store
from tests.test_utils import *


@patch('builtins.input', return_value="123456")
@patch('src.authentication.register.generate_2fa_code')
@patch('src.authentication.login.generate_2fa_code')
def test_role_check_workflow(mock_generate_login_2fa_code, mock_generate_register_2fa_code, mock_input):
    public_key, user_id = register_user_and_login(mock_generate_login_2fa_code, mock_generate_register_2fa_code)

    generate_and_store_aes_key(user_id)

    role = "receptionist"

    assign_user_to_role(user_id, role)
    print(f"User assigned the role of {role}.")

    patient_record = str({
        "blood_pressure": 120,
        "blood_glucose": 110
    })

    encrypted_patient_record = rsa_encrypt(patient_record, public_key)

    try:
        print("User attempting to store record in database...")
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
        print(f"User's {role} role does not have the necessary permissions to perform this operation.")
    except PermissionError as e:
        assert str(e) == (f"role_check.role_check_decorator -> User with ID {user_id} does not have required "
                          f"permissions for this operation.")
        print("PermissionError raised as expected. User does not have the required role.")
    else:
        assert False, "Expected PermissionError was not raised."
