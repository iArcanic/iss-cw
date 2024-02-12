# decrypt_data.py

from src.data_manager import *
from src.key_management.rsa_key_manager import *


# Decorator function RSA decrypt data
def rsa_decrypt_data_decorator(func):
    def wrapper(owner_id, data, *args, **kwargs):

        # Get all RSA private key entries from RSA HSM
        rsa_hsm_data = data_read("data/rsa_hsm.json")

        for key_info in rsa_hsm_data["rsa_keys"]:
            # Get correct RSA private key entry for record owner
            if key_info["user_id"] == owner_id:
                # Get RSA private key PEM string
                private_key_pem = key_info["key"]

                # Use RSA private key PEM string to perform RSA decryption on data
                decrypted_data = rsa_decrypt(data, private_key_pem)

                # Return to the original function''s arguments
                return func(
                    owner_id=owner_id,
                    data=data,
                    meta_data=kwargs.get("meta_data"),
                    permission=kwargs.get("permission"),
                    decrypted_data=decrypted_data,
                    individual_access=kwargs.get("individual_access")
                )

    return wrapper
