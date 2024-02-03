# main.py

from src.encryption import *
from src.decryption import *
from src.authentication.login import *
from src.authentication.register import *
from src.authentication.sso import *
from src.key_management.key_gen import *
from src.key_management.key_store import *
from src.key_management.key_retrieve import *

if __name__ == '__main__':

    # register_user("john_doe", "mySecurePassword", "07123456789")
    # login_user("john_doe", "mySecurePassword")
    single_sign_on("john_doe")

    aes_key = generate_aes_key()

    store_key_in_hsm("6967dcf0-fd7e-47ea-90a5-c10265650173", aes_key)

    user_retrieved_key = retrieve_key("6967dcf0-fd7e-47ea-90a5-c10265650173")
    print(user_retrieved_key.hex())

    # plaintext_data = "Hello World!"

    # ciphertext = aes_encrypt(aes_retrieved_key, plaintext_data.encode())
    # print("Encrypted Data:", ciphertext.hex())

    # decrypted_data = aes_decrypt(aes_retrieved_key, ciphertext[:16], ciphertext[16:])
    # print("Decrypted Data:", decrypted_data.decode())