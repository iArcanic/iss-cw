from datetime import datetime

from src.key_management.key_gen import generate_aes_key
from src.key_management.key_store import store_key_in_hsm
from src.record_management.record_retrieve import *
from src.record_management.record_store import *
from tests.authentication_workflow_tests import *

USERS_DB = "data/user_db.json"
USER_ROLES_DB = "data/user_roles_db.json"


@patch('builtins.input', return_value="123456")
@patch('src.authentication.register.generate_2fa_code')
@patch('src.authentication.login.generate_2fa_code')
def test_data_transmission_workflow(mock_generate_login_2fa_code, mock_generate_register_2fa_code, mock_input):

    public_key, user_id = registerUserAndLogin(mock_generate_login_2fa_code, mock_generate_register_2fa_code)
    generateAesKey(user_id)
    assignUserToRole(user_id, "doctor")

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
    assertPatientRecordRetriedDecreted(patient_record, record)


def assignUserToRole(user_id, role):
    new_user_role = {
        f"{user_id}": {
            "roles": [role]
        }
    }
    data_store(USER_ROLES_DB, new_user_role)


def generateAesKey(user_id):
    aes_key = generate_aes_key()
    store_key_in_hsm(user_id, aes_key)


def registerUserAndLogin(mock_generate_login_2fa_code, mock_generate_register_2fa_code):
    username = generate_random_username()
    password = generate_random_password()
    phone_number = "0123456789"
    mock_generate_register_2fa_code.return_value = "123456"
    register_user(username, password, phone_number)
    mock_generate_login_2fa_code.return_value = "123456"
    user_id, public_key = login_user(username, password)
    return public_key, user_id


def assertPatientRecordRetriedDecreted(data, record):
    replace = str(record[0]["data"]).replace("\"", "")
    assert replace == data
