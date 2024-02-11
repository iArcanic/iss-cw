from datetime import datetime

from src.record_management.record_retrieve import *
from src.record_management.record_store import *
from tests.authentication_workflow_tests import *
from tests.test_utils import *
from tests.test_utils import assign_user_to_role, generate_and_store_aes_key, assert_record_retrieved_decrypted

USERS_DB = "data/user_db.json"
USER_ROLES_DB = "data/user_roles_db.json"


@patch('builtins.input', return_value="123456")
@patch('src.authentication.register.generate_2fa_code')
@patch('src.authentication.login.generate_2fa_code')
def test_data_transmission_workflow(mock_generate_login_2fa_code, mock_generate_register_2fa_code, mock_input):

    public_key, user_id = register_user_and_login(mock_generate_login_2fa_code, mock_generate_register_2fa_code)

    generate_and_store_aes_key(user_id)

    role = "doctor"
    assign_user_to_role(user_id, role)
    print(f"User assigned the role of {role}.")

    patient_record = str({
        "blood_pressure": 120,
        "blood_glucose": 110
    })
    print(f'Raw patient_record: {str(patient_record)}')

    encrypted_patient_record = rsa_encrypt(patient_record, public_key)

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

    record = record_retrieve(
        owner_id=user_id,
        patient_id="0da97ef6-3af0-423f-884c-40cf23184a50",
        permission="MEDICAL_RECORD_VIEW"
    )

    assert len(record) == 1
    print(f'Data decrypted to original: {str(record[0]["data"])}')
    assert_record_retrieved_decrypted(patient_record, record[0])

