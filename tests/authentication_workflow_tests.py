from src.authentication.register import *
from src.authentication.login import *
from src.authentication.sso import *
from src.data_manager import *
from unittest.mock import patch
import random
import string

USERS_DB = "data/user_db.json"
THIRD_PARTY_DB = "data/third_party_db.json"


def generate_random_username(length=8):
    characters = string.ascii_letters + string.digits  # You can include other characters if needed
    return ''.join(random.choice(characters) for _ in range(length))


def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


@patch('builtins.input', return_value="123456")
@patch('src.authentication.register.generate_2fa_code')
@patch('src.authentication.login.generate_2fa_code')
def test_register_login_user(mock_generate_login_2fa_code, mock_generate_register_2fa_code, mock_input):
    username = generate_random_username()
    password = generate_random_password()
    phone_number = "0123456789"

    mock_generate_register_2fa_code.return_value = "123456"
    register_user(username, password, phone_number)

    users_data = data_read_return_empty_if_not_found(USERS_DB)

    assert username in users_data
    assert "user_id" in users_data[username]
    assert "hashed_password" in users_data[username]
    assert "salt" in users_data[username]
    assert "phone_number" in users_data[username]

    mock_generate_login_2fa_code.return_value = "123456"
    user_id, public_key = login_user(username, password)

    assert user_id == users_data[username]["user_id"]
    assert public_key is not None


def test_login_sso_login_not_allowed_directly():
    username = "joe_smith"

    single_sign_on(username)
    users_data = data_read_return_empty_if_not_found(USERS_DB)

    assert username in users_data
    assert login_user(username, "dummy_password") is None
