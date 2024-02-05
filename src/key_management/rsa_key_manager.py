import json

from cryptography.hazmat.primitives import serialization
from src.key_management.key_rsa import *


def replace_or_insert_key_from_file(user_id, new_key, file_path="data/rsa_hsm.json"):
    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
    except FileNotFoundError:
        json_data = {"rsa_keys": []}

    for entry in json_data["rsa_keys"]:
        if entry["user_id"] == user_id:
            entry["key"] = new_key
            break
    else:
        # If user_id not found, insert a new entry
        json_data["rsa_keys"].append({"user_id": user_id, "key": new_key})

    with open(file_path, 'w') as file:
        json.dump(json_data, file, indent=2)


def pem_convert_private_key(key):
    pem_format = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_format.decode('utf-8')


def pem_convert_public_key(key):
    pem_format = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_format.decode('utf-8')


def refresh_rsa_key(user_id):
    private_key, public_key = generate_key_pair()
    private_key_pem = pem_convert_private_key(private_key)
    replace_or_insert_key_from_file(user_id, private_key_pem)
    print("Private key: " + private_key_pem)
    print("Public key: " + pem_convert_public_key(public_key))
    return pem_convert_public_key(public_key)
