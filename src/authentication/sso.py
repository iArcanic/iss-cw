# sso.py
import uuid

from src.data_manager import *

THIRD_PARTY_DB = "data/third_party_db.json"
USER_DB = "data/user_db.json"


def single_sign_on(username):
    third_party_data = data_read(THIRD_PARTY_DB)
    users_data = data_read_return_empty_if_not_found(USER_DB)

    if username not in third_party_data:
        raise ValueError(f"sso.single_sign_on -> Username {username} not found. Please register with the third party "
                         f"provider first.")

    third_party_data = third_party_data[username]

    if third_party_data:
        new_user = {
            'user_id': str(uuid.uuid4()),
            'username': username,
            'third_party_status': True
        }

        users_data[username] = new_user

        # Add the new SSO user to the database
        data_store(USER_DB, users_data)

        # Third party identity provider would do their own authentication logic here
        print("sso.single_sign_on -> Third party authentication successful\nAuthentication logic by the third party "
              "provider.")
    else:
        print("sso.single_sign_on -> Third party authentication failed. SSO login aborted.")
