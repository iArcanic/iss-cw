from unittest.mock import patch

from src.authentication.sso import *
from tests.utils.test_utils import *

# Users database simulation
USERS_DB = "data/user_db.json"

# Third party provider database simulation
THIRD_PARTY_DB = "data/third_party_db.json"


# Patches to automate inputs when program prompts user for it
@patch('builtins.input', return_value="123456")
@patch('src.authentication.register.generate_2fa_code')
@patch('src.authentication.login.generate_2fa_code')
# Login and register workflow test case
def test_register_login_user(mock_generate_login_2fa_code, mock_generate_register_2fa_code, mock_input):
    # Generate a string random credentials to make a new unique user each time
    username = generate_random_username()
    password = generate_random_password()
    phone_number = "0123456789"

    # Ensure that the register 2FA is always the same code
    mock_generate_register_2fa_code.return_value = "123456"

    # Register the user
    register_user(username, password, phone_number)

    # Read all users from the Users database
    users_data = data_read_return_empty_if_not_found(USERS_DB)

    # Assertions to check whether the necessary JSON fields in the Users database exist
    assert username in users_data
    assert "user_id" in users_data[username]
    assert "hashed_password" in users_data[username]
    assert "salt" in users_data[username]
    assert "phone_number" in users_data[username]

    # Ensure that the login 2FA is always the same code
    mock_generate_login_2fa_code.return_value = "123456"

    # Login the user
    user_id, public_key = login_user(username, password)

    # Check whether the correct user has been logged in
    assert user_id == users_data[username]["user_id"]

    # Check whether a public key has been generated
    assert public_key is not None


# SSO (Single Sign-On) login workflow test case
def test_login_sso_login_not_allowed_directly():

    # Fixed user, as in the third party provider database
    username = "joe_smith"

    # SSO login the user with the fixed username
    single_sign_on(username)

    # Read all users from the Users database
    users_data = data_read_return_empty_if_not_found(USERS_DB)

    # Assertions to check whether the user actually exists
    assert username in users_data
    assert login_user(username, "dummy_password") is None
