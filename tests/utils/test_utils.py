import random
import string

from src.authentication.login import login_user
from src.authentication.register import register_user
from src.data_manager import data_store, data_read, data_read_return_empty_if_not_found
from src.key_management.key_gen import generate_aes_key
from src.key_management.key_store import store_aes_key

USER_ROLES_DB = "data/user_roles_db.json"


def generate_random_username(length=8):
    characters = string.ascii_letters + string.digits  # You can include other characters if needed
    return ''.join(random.choice(characters) for _ in range(length))


def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


def register_user_and_login(mock_generate_login_2fa_code, mock_generate_register_2fa_code):
    username = generate_random_username()
    password = generate_random_password()
    phone_number = "0123456789"
    mock_generate_register_2fa_code.return_value = "123456"
    register_user(username, password, phone_number)
    mock_generate_login_2fa_code.return_value = "123456"
    user_id, public_key = login_user(username, password)
    return public_key, user_id


def assign_user_to_role(user_id, role):
    user_roles_data = data_read_return_empty_if_not_found(USER_ROLES_DB)
    new_user_role = {
        "roles": [role]
    }
    user_roles_data[user_id] = new_user_role
    data_store(USER_ROLES_DB, user_roles_data)


def generate_and_store_aes_key(user_id):
    aes_key = generate_aes_key()
    store_aes_key(user_id, aes_key)


def assert_record_retrieved_decrypted(data, record):
    replace = str(record["data"]).replace("\"", "")
    assert replace == data


def create_user(mock_generate_login_2fa_code, mock_generate_register_2fa_code, role):
    public_key, user_id = register_user_and_login(mock_generate_login_2fa_code, mock_generate_register_2fa_code)
    generate_and_store_aes_key(user_id)
    assign_user_to_role(user_id, role)
    print(f"User assigned to role of {role}")
    return public_key, user_id
