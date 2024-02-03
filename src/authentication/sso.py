# sso.py

import json

THIRD_PARTY_DB = "data/third_party_db.json"

def single_sign_on(username):
    try:
        # Backend database for the third party identity provider
        with open(THIRD_PARTY_DB, 'r') as db_file:
            third_party_data = json.load(db_file)

    except FileNotFoundError:
        print("Third party database not found.")
        return

    if username not in third_party_data:
        print("Username not found. Please register with the third party provider first.")
        return

    third_party_data = third_party_data[username]

    if third_party_data:
        # Third party identity provider would do their own authentication logic here
        print("Third party authentication successful\nAuthentication logic by the third party provider.")
    else:
        print("Third party authentication failed. SSO login aborted.")