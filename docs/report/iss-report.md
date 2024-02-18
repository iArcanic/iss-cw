---
title: "ISS-CW3 Report"
author: "2242090"
bibliography: docs/report/references.bib
toc: true
toc-title: Table of Contents
toc-depth: 3
geometry: "left=1.25cm, right=1.25cm, top=1.25cm, bottom=1.25cm"
csl: docs/report/harvard-imperial-college-london.csl
---

# 1 Introduction

This report provides a comprehensive narrative description of the proposed cryptographic simulation for the healthcare provider, St. John's Clinic. The design has been implemented in such a way that it addresses the key security gaps within the clinic's data protection requirements, in order to align with compliance standards, and provide robust safeguarding mechanisms to secure sensitive data, that is, patient personal information, medical prescriptions, financial transactions, research data, and so on.

A current analysis of the cybersecurity practices which St. John's Clinic need to implement for security enhancement falls into the following areas of:

- Authentication
- Key management (and its relevant key lifecycle stages)
- Role based access control
- Cryptographic encryption algorithms
- Secure data transmission

# 2 Proposed simulation

For reference, please see [Appendix 5.1](#51-sequence-diagram) for the sequence diagram.

## 2.1 Authentication

A robust authentication framework means that only authorised users are allowed to interact with the system. It therefore regulates access to protected sensitive data and clinic services which should otherwise be inaccessible to unauthorised entities.

### 2.2.1 User registration

Under the assumption that any new users need to be registered securely with the system, a register function has been takes this into consideration. Since this is a simulation, the patient details this function processes are not that substantial to the overall functionality of the system, so only the following have been taken into account:

```python
def register_user(username, password, phone_number)
```

A `username` will help be a front-end unique identifier for users. A `password`, obviously, the user provides their custom password which will have the necessary hashing functions applied upon it. The `phone_number` parameter is just more placeholder registration data to fill out the JSON database entry.

To ensure that the username is unique, it reads the contents of the `USER_DB` JSON file and checks whether the chosen username exists or not – reflective of the actual clinic's system.

```python
users_data = data_read_return_empty_if_not_found(USER_DB)

if username in users_data:
    print(f"register.register_user -> Username '{username}' already exists. Please choose a different username.")
    return
```

Since we want the authentication framework to be secure, a simulation of two factor authentication is implemented. The two functions that are called in the code below, `generate_2fa_code()` and `send_2fa_code()`, are simple functions that mimic the process. One generates the code and the other "sends" that code to the user's phone. In this case, there is no "sending", so a simple on-screen message is returned. The user then needs to simply repeat this code to the program console and depending upon the code verification, the function flow continues.

```python
two_factor_code = generate_2fa_code()
send_2fa_code(phone_number, two_factor_code)
entered_code = input("Enter the 2FA code: ")

if entered_code == two_factor_code:
    print("register.register_user -> 2FA verification successful.")
else:
    print("register.register_user -> 2FA verification failed. Registration aborted.")
    return
```

Preparation to store the data in the database takes place here. First using the `uuid` library allows the generation of a UUID 4, and this is converted to a string format. A salt is generated for the hashing of the password using the `bcrypt` library. Note that using `.encode('utf-8')` allows for the password to be converted to bytes first.

```python
user_id = str(uuid.uuid4())
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
```

Finally, a new JSON object is created first as a Python dictionary. Note that the `hashed_password` and `salt` all have `.decode('utf-8')`, to allow them to be converted from bytes to strings. This is called JSON serialisation, since JSON does not support the storage of pure bytes.

Using another abstract function. `data_store()`, that I created to simplify file writing, this new JSON object is written to the JSON database file.

```python
new_user = {
    'user_id': user_id,
    'username': username,
    'hashed_password': hashed_password.decode('utf-8'),
    'salt': salt.decode('utf-8'),
    'phone_number': phone_number
}

users_data[username] = new_user
data_store(USER_DB, users_data)

print(f"register.register_user -> User '{username}' registered successfully. Login with your new account to continue.")
```

For more detail on `register.py`, see [Appendix 5.2.2.1](#5221-registerpy).

### 2.2.2 User login

The user, with their newly created account via the `register()` function, can now use that to login into the system and access the relevant data. The only credentials that they require for this is their `username` and `password` as such. These are passed as parameters to the function.

```python
def login_user(username, password)
```

Based on the given parameters to the function, `login()` then checks if the username exists, and if not, appropriately terminates the program flow.

```python
if username not in users_data:
    print("login.login_user -> Username not found. Please register first.")
    return
```

Using the username and the JSON document, it attempts to get all of the user's data. This data is then used for further processing.

```python
user_data = users_data[username]
stored_password_hash = user_data['hashed_password']
salt = user_data['salt']
phone_number = user_data.get('phone_number', None)
```

Since the function is hashed, the `bcrypt` Python library's `.checkpw` function compares the bytes of the entered user's password against the stored hash in the JSON database. Only then will the post processing actions take place if the function returns true based on the hash.

```python
if bcrypt.checkpw(entered_password.encode('utf-8'), stored_password_hash.encode('utf-8'))
```

Since two factor authentication was proposed for a secure authentication framework, a simulation of sending the one time password code is "sent" to the user's mobile device. If the verification passes, then the an RSA key under the user's ID is generated and stored (see []()) in the RSA HSM (Hardware Security Module). The `user_id` and `public_key` public key object is returned from the function for any post login actions.

```python
two_factor_code = generate_2fa_code()
send_2fa_code(phone_number, two_factor_code)
entered_code = input("Enter the 2FA code: ")

if entered_code == two_factor_code:
    print("login.login_user -> Login successful.")
    public_key = refresh_rsa_key(user_data["user_id"])
    return user_data['user_id'], public_key
```

## 2.2 Key management

## 2.3 Data transmission

## 2.4 Record management

## 2.5 Workflow simulation

# 3 Assumptions

# 4 Compliance and standards

# 5 Appendices

## 5.1 Sequence diagram

![](images/sequence-diagram-1.png)
![](images/sequence-diagram-2.png)

## 5.2 Implementation source code

### 5.2.1 Authentication

#### 5.2.2.1 `register.py`

```python
import uuid

import bcrypt

from src.authentication.two_fa import generate_2fa_code, send_2fa_code
from src.data_manager import *

# User database simulation
USER_DB = "data/user_db.json"


def register_user(username, password, phone_number):
    users_data = data_read_return_empty_if_not_found(USER_DB)

    # Check if the username already exists in the database
    if username in users_data:
        print(f"register.register_user -> Username '{username}' already exists. Please choose a different username.")
        return

    # Generate a 2FA code
    two_factor_code = generate_2fa_code()

    # Simulate sending the 2FA code to the user
    send_2fa_code(phone_number, two_factor_code)

    # Prompt the user to enter the received 2FA code
    entered_code = input("Enter the 2FA code: ")

    # Check if the entered code matches the generated 2FA code
    if entered_code == two_factor_code:
        print("register.register_user -> 2FA verification successful.")
    else:
        print("register.register_user -> 2FA verification failed. Registration aborted.")
        return

    # Generate a unique user_id using UUID
    user_id = str(uuid.uuid4())

    # Generate a random salt
    salt = bcrypt.gensalt()

    # Combine the password with the salt and hash it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Create a new user entry
    new_user = {
        'user_id': user_id,
        'username': username,
        'hashed_password': hashed_password.decode('utf-8'),  # Convert bytes to string for JSON serialization
        'salt': salt.decode('utf-8'),  # Convert bytes to string for JSON serialization
        'phone_number': phone_number
    }

    # Add the new user to the database
    users_data[username] = new_user

    # Save the updated database to the file
    data_store(USER_DB, users_data)

    print(f"register.register_user -> User '{username}' registered successfully. Login with your new account to "
          f"continue.")
```

#### 5.2.2.2 `login.py`

```python
import bcrypt

from src.authentication.two_fa import generate_2fa_code, send_2fa_code
from src.data_manager import *
from src.key_management.rsa_key_manager import *

# User database simulation
USER_DB = "data/user_db.json"


def login_user(username, password):
    users_data = data_read(USER_DB)

    # Check if the username exists in the database
    if username not in users_data:
        print("login.login_user -> Username not found. Please register first.")
        return

    if username in users_data and "third_party_status" in users_data[username]:
        print("login.login_user -> Please use SSO to login.")
        return

    user_data = users_data[username]
    stored_password_hash = user_data['hashed_password']
    salt = user_data['salt']
    phone_number = user_data.get('phone_number', None)

    # Get the user's password
    if password is None:
        entered_password = input("Enter your password: ")
    else:
        entered_password = password

    # Verify the entered password
    if bcrypt.checkpw(entered_password.encode('utf-8'), stored_password_hash.encode('utf-8')):
        # If the password is correct, proceed with 2FA verification
        two_factor_code = generate_2fa_code()
        send_2fa_code(phone_number, two_factor_code)

        entered_code = input("Enter the 2FA code: ")

        if entered_code == two_factor_code:
            print("login.login_user -> Login successful.")
            # Every time the user logins the RSA key is regenerated
            # Used for transferring data across multiple clinic services
            public_key = refresh_rsa_key(user_data["user_id"])
            return user_data['user_id'], public_key
        else:
            print("login.login_user -> 2FA verification failed. Login aborted.")
    else:
        print("login.login_user -> Incorrect password. Login aborted.")
```

# 6 References
