# two_fa.py

import random


def generate_2fa_code():
    # Generate a random 6-digit code for 2FA
    return ''.join(str(random.randint(0, 9)) for _ in range(6))


def send_2fa_code(phone_number, code):
    # Simulate sending the 2FA code to the user's phone (replace this with actual SMS or authenticator app integration)
    print(f"two_fa.send_2fa_code -> 2FA code '{code}' sent to {phone_number}.")
