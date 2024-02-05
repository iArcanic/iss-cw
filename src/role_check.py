# role_check.py

import json

USER_ROLES_DB = "../data/user_roles_db.json"
ROLE_PERMISSIONS_DB = "../data/role_permissions_db.json"


def role_check_decorator(func):
    def wrapper(owner_id, *args, **kwargs):
        try:
            with open(USER_ROLES_DB, 'r') as user_roles_file:
                user_roles_data = json.load(user_roles_file)

            with open(ROLE_PERMISSIONS_DB, 'r') as role_permissions_file:
                role_permissions_data = json.load(role_permissions_file)

        except FileNotFoundError:
            print(f"User roles database or role permissions database not found.")
            return

        if owner_id in user_roles_data:
            user_roles = user_roles_data[owner_id]["roles"]

            for role in user_roles:
                if role in role_permissions_data:
                    # Check if the function's name corresponds to a permission
                    permission_name = kwargs.get("permission", "").upper()
                    if permission_name in role_permissions_data[role]["permissions"]:
                        return func(owner_id, *args, **kwargs)
                    else:
                        raise PermissionError(
                            f"User with ID {owner_id} does not have required permissions for this operation.")
                else:
                    print(f"Role {role} not found in role permissions data.")
        else:
            print(f"User with ID {owner_id} not found in user roles data.")

    return wrapper
