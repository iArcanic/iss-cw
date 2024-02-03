# authentication.py

import secrets
import json
import bcrypt
import uuid
import random

USER_DB = "data/user_db.json"

def generate_2fa_code():
    # Generate a random 6-digit code for 2FA
    return ''.join(str(random.randint(0, 9)) for _ in range(6))

def send_2fa_code(phone_number, code):
    # Simulate sending the 2FA code to the user's phone (replace this with actual SMS or authenticator app integration)
    print(f"2FA code '{code}' sent to {phone_number}.")

def register_user(username, password, phone_number):
    try:
        # Try to open the existing database file
        with open(USER_DB, 'r') as db_file:
            users_data = json.load(db_file)

    except FileNotFoundError:
        # If the file is not found, create an empty database
        users_data = {}

    # Check if the username already exists in the database
    if username in users_data:
        print(f"Username '{username}' already exists. Please choose a different username.")
        return

    # Generate a 2FA code
    two_factor_code = generate_2fa_code()

    # Simulate sending the 2FA code to the user
    send_2fa_code(phone_number, two_factor_code)

    # Prompt the user to enter the received 2FA code
    entered_code = input("Enter the 2FA code: ")

    # Check if the entered code matches the generated 2FA code
    if entered_code == two_factor_code:
        print("2FA verification successful.")
    else:
        print("2FA verification failed. Registration aborted.")
        return

    # Generate a unique user_id using UUID
    user_id = str(uuid.uuid4())

    # Generate a random salt
    salt = bcrypt.gensalt()

    # Combine the password with the salt and hash it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Create a new user entry
    new_user = {
        'user_id': user_id,
        'username': username,
        'hashed_password': hashed_password.decode('utf-8'),  # Convert bytes to string for JSON serialization
        'salt': salt.decode('utf-8'),  # Convert bytes to string for JSON serialization
        'phone_number': phone_number
    }

    # Add the new user to the database
    users_data[username] = new_user

    # Save the updated database to the file
    with open(USER_DB, 'w') as db_file:
        json.dump(users_data, db_file, indent=2)

    print(f"User '{username}' registered successfully.")

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
        else:
            print("2FA verification failed. Login aborted.")
    else:
        print("Incorrect password. Login aborted.")