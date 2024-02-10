# sso.py

import json

THIRD_PARTY_DB = "data/third_party_db.json"


def single_sign_on(username):
    try:
        # Backend database for the third party identity provider
        with open(THIRD_PARTY_DB, 'r') as db_file:
            third_party_data = json.load(db_file)

    except FileNotFoundError:
        print(f"sso.single_sign_on -> {THIRD_PARTY_DB} not found.")
        return

    if username not in third_party_data:
        print(f"sso.single_sign_on -> Username {username} not found. Please register with the third party provider "
              f"first.")
        return

    third_party_data = third_party_data[username]

    if third_party_data:
        # Third party identity provider would do their own authentication logic here
        print("sso.single_sign_on -> Third party authentication successful\nAuthentication logic by the third party "
              "provider.")
    else:
        print("sso.single_sign_on -> Third party authentication failed. SSO login aborted.")
