import random
import string

from src.authentication.login import login_user
from src.authentication.register import register_user
from src.data_manager import data_store
from src.key_management.key_gen import generate_aes_key
from src.key_management.key_store import store_key_in_hsm

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
    new_user_role = {
        f"{user_id}": {
            "roles": [role]
        }
    }
    data_store(USER_ROLES_DB, new_user_role)


def generate_and_store_aes_key(user_id):
    aes_key = generate_aes_key()
    store_key_in_hsm(user_id, aes_key)


def assert_patient_record_retrieved_decrypted(data, record):
    replace = str(record[0]["data"]).replace("\"", "")
    assert replace == data
