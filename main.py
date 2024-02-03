# main.py

from src.key_gen import *
from src.encryption import *
from src.decryption import *
from src.key_management import *
from src.authentication import *
from src.register import *

if __name__ == '__main__':

    register_user("john_doe", "mySecurePassword", "07123456789")

    # login("john", "poothika")

    # aes_key = generate_aes_key()

    # keys = {
    #     "aes_key": aes_key
    # }

    # print(store_keys_in_hsm(keys))
    # aes_retrieved_key = retrieve_key("aes_key")

    # plaintext_data = "Hello World!"

    # ciphertext = aes_encrypt(aes_retrieved_key, plaintext_data.encode())
    # print("Encrypted Data:", ciphertext.hex())

    # decrypted_data = aes_decrypt(aes_retrieved_key, ciphertext[:16], ciphertext[16:])
    # print("Decrypted Data:", decrypted_data.decode())