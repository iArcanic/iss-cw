# role_check.py

import json

USER_ROLES_DB = "data/user_roles_db.json"

def role_check_decorator(func):
    def wrapper(*args, **kwargs):
        try:
            with open(USER_ROLES_DB, 'r') as db_file:
                user_roles_data = json.load(db_file)
        except FileNotFoundError:
            print(f"User roles database not found.")
            return

        user_id = kwargs.get("user_id", None)

        if user_id is not None and user_id in user_roles_data.get("user_roles", {}):
            user_roles = user_roles_data["user_roles"][user_id]["roles"]
            print(f"User with ID {user_id} has roles: {user_roles}")
            result = func(*args, **kwargs)
            return result
        else:
            print(f"User with ID {user_id} not found or has no roles.")
            return

    return wrapper