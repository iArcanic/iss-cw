# role_check.py

import json

# User roles database simulation
USER_ROLES_DB = "data/user_roles_db.json"

# Role permissions database simulation
ROLE_PERMISSIONS_DB = "data/role_permissions_db.json"


def role_check_decorator(func):
    def wrapper(owner_id, *args, **kwargs):
        try:
            with open(USER_ROLES_DB, 'r') as user_roles_file:
                # Get all the users with their relevant allocated roles
                user_roles_data = json.load(user_roles_file)

            with open(ROLE_PERMISSIONS_DB, 'r') as role_permissions_file:
                # Get all permissions
                role_permissions_data = json.load(role_permissions_file)

        except FileNotFoundError:
            print(f"role_check.role_check_decorator -> {USER_ROLES_DB} database or {ROLE_PERMISSIONS_DB} database not "
                  f"found.")
            return

        if owner_id in user_roles_data:
            # Get all the roles which the user has been granted
            user_roles = user_roles_data[owner_id]["roles"]

            for role in user_roles:
                # Check if the role exists
                if role in role_permissions_data:
                    # Check if the function's name corresponds to a permission
                    permission_name = kwargs.get("permission", "").upper()
                    # Get the correct permission from permissions database
                    if permission_name in role_permissions_data[role]["permissions"]:
                        # Return to the original function
                        return func(owner_id, *args, **kwargs)
                    else:
                        # Terminate the program if the user does not have the relevant role
                        raise PermissionError(
                            f"role_check.role_check_decorator -> User with ID {owner_id} does not have required "
                            f"permissions for this operation.")
                else:
                    # Terminate the program if the role is not found
                    print(f"role_check.role_check_decorator -> Role {role} not found in role permissions data.")
        else:
            # Terminate the program if the user is not found
            print(f"role_check.role_check_decorator -> User with ID {owner_id} not found in user roles data.")

    return wrapper
