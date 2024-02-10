# decrypt_data.py

from src.data_manager import *
from src.key_management.rsa_key_manager import *


def rsa_decrypt_data_decorator(func):
    def wrapper(owner_id, data, *args, **kwargs):
        rsa_hsm_data = data_read("data/rsa_hsm.json")

        for key_info in rsa_hsm_data["rsa_keys"]:
            if key_info["user_id"] == owner_id:
                private_key_pem = key_info["key"]
                decrypted_data = rsa_decrypt(data, private_key_pem)
                return func(
                    owner_id=owner_id,
                    data=data,
                    meta_data=kwargs.get("meta_data"),
                    permission=kwargs.get("permission"),
                    decrypted_data=decrypted_data
                )

    return wrapper
