# login.py

import secrets
import json
import bcrypt
import uuid
from src.authentication.two_fa import generate_2fa_code, send_2fa_code

USER_DB = "data/user_db.json"

def login_user(username, password):
    try:
        with open(USER_DB, 'r') as db_file:
            users_data = json.load(db_file)

    except FileNotFoundError:
        print("User database not found. Please register first.")
        return

    # Check if the username exists in the database
    if username not in users_data:
        print("Username not found. Please register first.")
        return

    user_data = users_data[username]
    stored_password_hash = user_data['hashed_password']
    salt = user_data['salt']
    phone_number = user_data.get('phone_number', None)

    # Get the user's password
    entered_password = input("Enter your password: ")

    # Verify the entered password
    if bcrypt.checkpw(entered_password.encode('utf-8'), stored_password_hash.encode('utf-8')):
        # If the password is correct, proceed with 2FA verification
        two_factor_code = generate_2fa_code()
        send_2fa_code(phone_number, two_factor_code)

        entered_code = input("Enter the 2FA code: ")

        if entered_code == two_factor_code:
            print("Login successful.")
            return user_data['user_id']
        else:
            print("2FA verification failed. Login aborted.")
    else:
        print("Incorrect password. Login aborted.")