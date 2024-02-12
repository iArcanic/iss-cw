from datetime import datetime
from unittest.mock import patch

from src.key_management.rsa_key_manager import rsa_encrypt
from src.record_management.record_retrieve import record_retrieve_by_id
from src.record_management.record_store import record_store
from tests.utils.test_utils import create_user, assert_record_retrieved_decrypted


# Patches to automate inputs when program prompts user for it
@patch('builtins.input', return_value="123456")
@patch('src.authentication.register.generate_2fa_code')
@patch('src.authentication.login.generate_2fa_code')
def test_record_individual_access_workflow(mock_generate_login_2fa_code, mock_generate_register_2fa_code, mock_input):
    # Register, login, and allocate make a "research_scientist" new user
    rs_public_key, rs_user_id = create_user(mock_generate_login_2fa_code, mock_generate_register_2fa_code,
                                            "research_scientist")

    # Register, login, and allocate make a "doctor" new user
    dr_public_key, dr_user_id = create_user(mock_generate_login_2fa_code, mock_generate_register_2fa_code, "doctor")

    # Sample research record data
    research_record = str({
        "study_id": "CR001",
        "title": "Drug X Safety Study",
        "phase": "Phase II"
    })
    print(f'Raw research_record: {str(research_record)}')

    # Encrypt sample research record data with new "research_scientist" user's public key
    encrypted_research_record = rsa_encrypt(research_record, rs_public_key)

    print("Research scientist attempting to store record in database...")
    print("NOTE: Record does not have individual access permission for doctor.")
    # Perform record store, but do not give any individual access
    research_record_id = record_store(
        owner_id=rs_user_id,
        data=encrypted_research_record,
        meta_data={
            "data_type": "RESEARCH_RECORD",
            "timestamp": datetime.utcnow().isoformat()
        },
        permission="EDIT_RESEARCH_RECORDS"
    )

    try:
        print("Doctor attempting to retrieve research record from database...")
        # Perform record retrieve with "doctor" user
        record_retrieve_by_id(research_record_id, dr_user_id)
    except PermissionError as e:
        # Check whether the error received is the same error as in the role_check_decorator
        assert str(e) == (f"record_retrieve.record_retrieve_by_id -> User with ID {dr_user_id} does not have required "
                          f"permissions for this operation.")
        print(f"PermissionError, {e}, raised as expected. User does not have the required role.")
    else:
        # Otherwise fail the test since the error did not arise
        assert False, "Expected PermissionError was not raised."

    print("Research scientist attempting to store record in records database...")
    print("NOTE: Record does have individual access permission for doctor.")
    # Perform record store, but this time, give individual access to "doctor" user
    research_record_id = record_store(
        owner_id=rs_user_id,
        data=encrypted_research_record,
        meta_data={
            "data_type": "RESEARCH_RECORD",
            "timestamp": datetime.utcnow().isoformat()
        },
        permission="EDIT_RESEARCH_RECORDS",
        # Individual access to "doctor" user
        individual_access=[dr_user_id]
    )

    print("Doctor attempting to retrieve research record from records database...")
    # Perform record retrieve with "doctor" user
    record = record_retrieve_by_id(research_record_id, dr_user_id)

    print(f'Record retrieved based on authorised invitation individually: {str(record["data"])}')
    # Check whether the record before encryption and after encryption are exactly the same
    assert_record_retrieved_decrypted(research_record, record)
