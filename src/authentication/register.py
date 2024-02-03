# register.py

import secrets
import json
import bcrypt
import uuid
from src.authentication.two_fa import generate_2fa_code, send_2fa_code

USER_DB = "data/user_db.json"

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