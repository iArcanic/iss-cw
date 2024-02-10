import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


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
    return pem_convert_public_key(public_key)


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(data, public_key_pem):
    public_key = load_public_key_from_pem_string(public_key_pem)
    ciphertext = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(ciphertext, private_key_pem):
    private_key = load_private_key_from_pem_string(private_key_pem)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode("utf-8")


def load_private_key_from_pem_string(pem_string):
    private_key = serialization.load_pem_private_key(
        pem_string.encode(),
        password=None,
        backend=default_backend()
    )
    return private_key


def load_public_key_from_pem_string(pem_string):
    public_key = serialization.load_pem_public_key(
        pem_string.encode(),
        backend=default_backend()
    )
    return public_key
