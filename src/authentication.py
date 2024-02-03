# authentication.py

import secrets
import json
import bcrypt
import random

USER_DB = "data/user_db.json"

def generate_2fa_code():
    # Generate a random 6-digit code for 2FA
    return ''.join(str(random.randint(0, 9)) for _ in range(6))

def send_2fa_code(phone_number, code):
    # Simulate sending the 2FA code to the user's phone (replace this with actual SMS or authenticator app integration)
    print(f"2FA code '{code}' sent to {phone_number}.")

def login(username, password):
    try:
        with open(USER_DB) as f:
            print("1")

            users = json.load(f)

            print("2")

            stored_password_hash = users[username]["password_hash"]

            print("stored_password_hash: " + stored_password_hash)

            password_bytes = password.encode('utf-8')
            password_hash = bcrypt.hashpw(password_bytes, stored_password_hash.encode())

            if stored_password_hash == password_hash.decode('utf-8'):
                print("Password hashes match!")
                # return generate_access_token(username)
            else:
                print("Password hashes do not match!")
                return None

    except (FileNotFoundError):
        print(f"Invalid username or database {USER_DB} not found!")

    return None

def generate_access_token(username):
    token = secrets.token_hex(16)
    return token